"""
Main milter daemon.

Implements the Milter protocol callbacks, integrates the rule engine,
and applies actions (x-headers, spam score, subject prefix) to
messages that trigger rules.
"""

from __future__ import annotations

import atexit
import email
import email.policy
import logging
import os
import re
import signal
import sys
from email.header import decode_header
from pathlib import Path
from typing import Any, Optional

from .checks.base import BaseCheck
from .checks.domain_age import DomainAgeCheck
from .checks.false_reply import FalseReplyCheck
from .checks.fuzzy_domain import FuzzyDomainCheck
from .config import AppConfig, load_config
from .engine import FiredAction, RuleEngine
from .rdap_client import RdapClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PID file management
# ---------------------------------------------------------------------------

_pid_file_path: Optional[str] = None
"""Tracks the current PID file path so signal handlers can clean up."""


def _write_pid_file(pid_file: str) -> None:
    """
    Write the current process PID to *pid_file*.

    If the file already exists and the recorded PID is still alive,
    the function raises ``SystemExit`` to prevent duplicate daemons.
    A stale PID file (process no longer running) is overwritten.
    """
    global _pid_file_path  # noqa: PLW0603
    path = Path(pid_file)

    # Check for a running previous instance
    if path.is_file():
        try:
            old_pid = int(path.read_text(encoding="utf-8").strip())
            if old_pid > 0 and _is_process_running(old_pid):
                logger.error(
                    "Another instance is already running (PID %d, pid_file=%s). "
                    "Remove %s if the previous instance has crashed.",
                    old_pid, pid_file, pid_file,
                )
                sys.exit(1)
            else:
                logger.info(
                    "Stale PID file found (PID %d no longer running), overwriting",
                    old_pid,
                )
        except (ValueError, OSError) as exc:
            logger.warning("Could not read existing PID file %s: %s", pid_file, exc)

    # Ensure the parent directory exists
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create PID file directory %s: %s", path.parent, exc)

    # Write the PID
    try:
        path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        _pid_file_path = pid_file
        logger.info("PID %d written to %s", os.getpid(), pid_file)
    except OSError as exc:
        logger.error("Could not write PID file %s: %s", pid_file, exc)
        # Non-fatal — the milter can still operate without a PID file


def _remove_pid_file() -> None:
    """Remove the PID file on clean shutdown."""
    global _pid_file_path  # noqa: PLW0603
    if _pid_file_path is None:
        return
    path = Path(_pid_file_path)
    try:
        if path.is_file():
            # Only remove if the file contains our PID (avoid race with a new instance)
            content = path.read_text(encoding="utf-8").strip()
            if content == str(os.getpid()):
                path.unlink()
                logger.info("PID file %s removed", _pid_file_path)
            else:
                logger.debug(
                    "PID file %s contains PID %s (we are %d), not removing",
                    _pid_file_path, content, os.getpid(),
                )
    except OSError as exc:
        logger.warning("Could not remove PID file %s: %s", _pid_file_path, exc)
    finally:
        _pid_file_path = None


def _is_process_running(pid: int) -> bool:
    """Check whether a process with the given *pid* is still alive."""
    try:
        os.kill(pid, 0)  # signal 0 = existence check
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we can't signal it — it's still running
        return True
    except OSError:
        return False


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM / SIGINT — clean up PID file and exit."""
    sig_name = signal.Signals(signum).name
    logger.info("Received %s, shutting down", sig_name)
    _remove_pid_file()
    sys.exit(0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_header_value(raw: str) -> str:
    """Decode an RFC-2047 encoded header value to a plain string."""
    parts = decode_header(raw)
    decoded: list[str] = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded.append(data.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(data)
    return "".join(decoded)


# ---------------------------------------------------------------------------
# Milter application
# ---------------------------------------------------------------------------

def _create_milter_class() -> type:
    """
    Create and return the AmavisMilter class.

    We defer the ``import Milter`` to runtime so that the rest of the
    package (config, checks, engine) can be imported without having
    libmilter / pymilter installed — useful for testing and CI.
    """
    import Milter  # type: ignore[import-untyped]
    from Milter.utils import parseaddr  # type: ignore[import-untyped]

    class AmavisMilter(Milter.Milter):
        """
        Milter implementation that applies spam-analysis rules.

        Lifecycle callbacks used:
          - envfrom  : capture envelope sender
          - header   : collect headers one by one
          - eoh      : all headers received → run checks, apply actions
          - eom      : end-of-message — final modifications
        """

        # Class-level engine — shared across all connections.
        _engine: Optional[RuleEngine] = None

        def __init__(self) -> None:  # noqa: D107
            self._sender: str = ""
            self._sender_domain: str = ""
            self._subject: str = ""
            self._headers: dict[str, list[str]] = {}
            self._fired_actions: list[FiredAction] = []
            self._raw_headers: list[tuple[str, str]] = []

        # ---- Milter callbacks --------------------------------------------

        @Milter.noreply
        def envfrom(self, mailfrom: str, *args: Any) -> int:  # noqa: N802
            """Handle MAIL FROM — capture the envelope sender."""
            _, addr = parseaddr(mailfrom)
            self._sender = addr or mailfrom
            self._sender_domain = (
                self._sender.rsplit("@", 1)[-1].lower()
                if "@" in self._sender else ""
            )
            logger.info(
                "Envelope sender: %s (domain: %s)",
                self._sender, self._sender_domain,
            )
            return Milter.CONTINUE

        @Milter.noreply
        def header(self, name: str, value: str) -> int:
            """Collect each header as it arrives."""
            key = name.lower()
            self._headers.setdefault(key, []).append(value)
            self._raw_headers.append((name, value))

            if key == "subject":
                self._subject = _decode_header_value(value)

            return Milter.CONTINUE

        def eoh(self) -> int:
            """
            End-of-headers — run all checks and prepare actions.

            We do NOT modify the message here (milter protocol requires
            modifications in eom), but we compute everything so that
            eom can apply changes quickly.
            """
            if not self._sender_domain:
                logger.info("No sender domain, skipping checks")
                return Milter.CONTINUE

            raw_msg = (
                "".join(f"{n}: {v}\r\n" for n, v in self._raw_headers)
                + "\r\n"
            )
            message = email.message_from_string(
                raw_msg, policy=email.policy.default,
            )

            assert self.__class__._engine is not None
            self._fired_actions = self.__class__._engine.evaluate(
                sender=self._sender,
                sender_domain=self._sender_domain,
                subject=self._subject,
                headers=self._headers,
                message=message,
            )

            if self._fired_actions:
                total_score = self.__class__._engine.get_total_spam_increase(
                    self._fired_actions,
                )
                logger.warning(
                    "Message from %s triggered %d rule(s), "
                    "total spam increase: %.1f",
                    self._sender,
                    len(self._fired_actions),
                    total_score,
                )
            else:
                logger.info(
                    "No rules triggered for message from %s",
                    self._sender,
                )

            return Milter.CONTINUE

        def eom(self) -> int:
            """
            End-of-message — apply all fired actions.

            For each fired action:
              1. Add X-header
              2. Increase spam score (via X-Spam-Score header)
              3. Optionally add subject prefix
            """
            if not self._fired_actions:
                return Milter.CONTINUE

            engine = self.__class__._engine
            assert engine is not None
            total_score = engine.get_total_spam_increase(self._fired_actions)

            # 1. Per-trigger X-headers
            for action in self._fired_actions:
                header_name = action.action.header_name
                header_value = action.action.header_value
                full_value = (
                    f"{header_value}; reason={action.result.reason}"
                )
                self.addheader(header_name, full_value, -1)
                logger.debug(
                    "Added header %s: %s", header_name, full_value,
                )

            # 2. Aggregate spam score header
            existing_score = self._headers.get("x-spam-score", ["0"])[0]
            try:
                base_score = float(
                    re.sub(r"[^\d.\-+]", "", existing_score)
                )
            except (ValueError, TypeError):
                base_score = 0.0

            new_score = base_score + total_score
            self.addheader(
                "X-Spam-Score",
                f"{new_score:.1f} (+{total_score:.1f} from milter)",
                -1,
            )

            # 3. Subject prefix
            prefix = engine.get_subject_prefix(self._fired_actions)
            if prefix and self._subject:
                new_subject = f"{prefix} {self._subject}"
                self.chgheader("Subject", 1, new_subject)
                logger.info(
                    "Subject prefixed: %s → %s",
                    self._subject, new_subject,
                )

            return Milter.CONTINUE

        def close(self) -> int:
            """Connection cleanup."""
            return Milter.CONTINUE

        def abort(self) -> int:
            """Milter abort — reset state."""
            self._fired_actions.clear()
            return Milter.CONTINUE

    return AmavisMilter


# ---------------------------------------------------------------------------
# Factory / startup
# ---------------------------------------------------------------------------

def _build_engine(config: AppConfig) -> RuleEngine:
    """
    Build the rule engine with all check instances from config.
    """
    engine = RuleEngine(config)
    rdap = RdapClient(config.rdap)

    for tc in config.triggers:
        if not tc.enabled:
            continue
        check: BaseCheck
        if tc.type == "domain_age":
            check = DomainAgeCheck(tc.name, tc.params, rdap)
        elif tc.type == "false_reply":
            check = FalseReplyCheck(tc.name, tc.params)
        elif tc.type == "fuzzy_domain":
            check = FuzzyDomainCheck(tc.name, tc.params)
        else:
            logger.warning(
                "Unknown trigger type '%s' for trigger '%s'",
                tc.type, tc.name,
            )
            continue
        engine.register_check(check)

    return engine


def _setup_logging(config: AppConfig) -> None:
    """Configure logging from AppConfig."""
    handlers: list[logging.Handler] = []

    if config.logging.file:
        handlers.append(
            logging.FileHandler(config.logging.file, encoding="utf-8")
        )
    else:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=getattr(logging, config.logging.level.upper(), logging.INFO),
        format=config.logging.format,
        handlers=handlers,
    )


def run_milter(config_path: str) -> None:
    """
    Load configuration, build the engine, and start the milter daemon.
    """
    import Milter  # type: ignore[import-untyped]

    config = load_config(config_path)
    _setup_logging(config)

    engine = _build_engine(config)

    # Create the milter class (deferred import of Milter base class)
    AmavisMilter = _create_milter_class()
    AmavisMilter._engine = engine  # type: ignore[attr-defined]

    logger.info(
        "Starting %s on %s with %d triggers and %d groups",
        config.milter.name,
        config.milter.socket,
        len(config.triggers),
        len(config.groups),
    )

    # Write PID file before entering the milter loop
    if config.milter.pid_file:
        _write_pid_file(config.milter.pid_file)
        # Register cleanup on normal exit and signals
        atexit.register(_remove_pid_file)
        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

    # Register the milter factory
    Milter.factory = AmavisMilter  # type: ignore[attr-defined]

    # Set milter capabilities
    flags = Milter.CHGHDRS | Milter.ADDHDRS | Milter.CHGBODY
    Milter.set_flags(flags)

    try:
        Milter.runmilter(
            config.milter.name,
            config.milter.socket,
            config.milter.timeout,
        )
    finally:
        # Ensure PID file cleanup even if runmilter raises
        _remove_pid_file()

