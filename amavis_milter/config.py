"""
Configuration loader for amavis-milter.
Reads and validates TOML configuration files.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        raise ImportError(
            "tomli is required for Python <3.11. Install it: pip install tomli"
        )


# ---------------------------------------------------------------------------
# Data classes describing every configurable entity
# ---------------------------------------------------------------------------

@dataclass
class ActionConfig:
    """Actions applied when a rule triggers."""

    header_name: str = "X-Spam-Flag"
    header_value: str = "YES"
    spam_score_increase: float = 1.0
    subject_prefix: str = ""


@dataclass
class TriggerConfig:
    """A single atomic trigger (one check)."""

    name: str
    type: str  # "domain_age" | "false_reply" | "fuzzy_domain"
    enabled: bool = True
    params: dict[str, Any] = field(default_factory=dict)
    action: ActionConfig = field(default_factory=ActionConfig)


@dataclass
class GroupConfig:
    """A group of triggers that forms a compound rule."""

    name: str
    mode: str = "all"  # "all" | "any" | "majority"
    triggers: list[str] = field(default_factory=list)
    enabled: bool = True
    action: ActionConfig = field(default_factory=ActionConfig)


@dataclass
class RdapConfig:
    """RDAP client settings."""

    service_url: str = "https://who-dat.as93.net"
    timeout: float = 10.0
    cache_ttl: int = 86400  # seconds
    cache_max_size: int = 10000
    max_concurrent: int = 10  # max parallel RDAP requests


@dataclass
class DomainAgeParams:
    """Parameters for the domain-age check."""

    max_age_days: int = 30
    trusted_domains: list[str] = field(default_factory=list)
    tld_priorities: dict[str, int] = field(default_factory=dict)


@dataclass
class FuzzyDomainParams:
    """Parameters for the fuzzy-domain check."""

    similarity_threshold: float = 0.75
    min_length: int = 4
    known_domains: list[str] = field(default_factory=list)
    history_file: str = ""  # path to JSON file with seen domains
    history_max_entries: int = 50000


@dataclass
class FalseReplyParams:
    """Parameters for the false-reply check."""

    reply_prefixes: list[str] = field(default_factory=lambda: ["Re:", "RE:", "Fw:", "FW:"])
    check_in_reply_to: bool = True
    check_references: bool = True


@dataclass
class MilterConfig:
    """Top-level milter daemon settings."""

    socket: str = "inet:8899@127.0.0.1"
    name: str = "amavis-milter"
    timeout: int = 300
    pid_file: str = "/opt/zimbra/log/milter.pid"
    # When True, any known subject_prefix (defined by any trigger or group in
    # the config) that already leads the Subject is stripped before the new
    # combined prefix is prepended. Prevents duplicate prefixes piling up when
    # a message is re-processed by the milter.
    strip_existing_prefixes: bool = True
    # Spam flag: when the total spam score increase from all fired triggers
    # and groups reaches this threshold, an additional header is added to
    # the message (e.g. X-Spam-Status: spam).
    spam_threshold: float = 5.0
    spam_flag_header: str = "X-Spam-Status"
    spam_flag_value: str = "spam"


@dataclass
class LoggingConfig:
    """Logging settings."""

    level: str = "INFO"
    file: str = ""  # empty → stderr
    format: str = "%(asctime)s [%(levelname)s] [%(message_id)s] %(name)s: %(message)s"


@dataclass
class AppConfig:
    """Full application configuration."""

    milter: MilterConfig = field(default_factory=MilterConfig)
    rdap: RdapConfig = field(default_factory=RdapConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    triggers: list[TriggerConfig] = field(default_factory=list)
    groups: list[GroupConfig] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _parse_action(raw: dict[str, Any]) -> ActionConfig:
    return ActionConfig(
        header_name=raw.get("header_name", "X-Spam-Flag"),
        header_value=raw.get("header_value", "YES"),
        spam_score_increase=float(raw.get("spam_score_increase", 1.0)),
        subject_prefix=raw.get("subject_prefix", ""),
    )


def _parse_trigger(name: str, raw: dict[str, Any]) -> TriggerConfig:
    return TriggerConfig(
        name=name,
        type=raw.get("type", "domain_age"),
        enabled=raw.get("enabled", True),
        params=raw.get("params", {}),
        action=_parse_action(raw.get("action", {})),
    )


def _parse_group(name: str, raw: dict[str, Any]) -> GroupConfig:
    return GroupConfig(
        name=name,
        mode=raw.get("mode", "all"),
        triggers=raw.get("triggers", []),
        enabled=raw.get("enabled", True),
        action=_parse_action(raw.get("action", {})),
    )


def load_config(path: str | Path) -> AppConfig:
    """Load and validate configuration from a TOML file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Configuration file not found: {p}")

    with p.open("rb") as f:
        data: dict[str, Any] = tomllib.load(f)

    # --- milter section ---
    raw_milter = data.get("milter", {})
    milter = MilterConfig(
        socket=raw_milter.get("socket", "inet:8899@127.0.0.1"),
        name=raw_milter.get("name", "amavis-milter"),
        timeout=raw_milter.get("timeout", 300),
        pid_file=raw_milter.get("pid_file", "/opt/zimbra/log/milter.pid"),
        strip_existing_prefixes=bool(raw_milter.get("strip_existing_prefixes", True)),
        spam_threshold=float(raw_milter.get("spam_threshold", 5.0)),
        spam_flag_header=raw_milter.get("spam_flag_header", "X-Spam-Status"),
        spam_flag_value=raw_milter.get("spam_flag_value", "spam"),
    )

    # --- rdap section ---
    raw_rdap = data.get("rdap", {})
    rdap = RdapConfig(
        service_url=raw_rdap.get("service_url", "https://who-dat.as93.net"),
        timeout=float(raw_rdap.get("timeout", 10.0)),
        cache_ttl=raw_rdap.get("cache_ttl", 86400),
        cache_max_size=raw_rdap.get("cache_max_size", 10000),
        max_concurrent=raw_rdap.get("max_concurrent", 10),
    )

    # --- logging section ---
    raw_log = data.get("logging", {})
    logging_cfg = LoggingConfig(
        level=raw_log.get("level", "INFO"),
        file=raw_log.get("file", ""),
        format=raw_log.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s"),
    )

    # --- triggers section ---
    triggers: list[TriggerConfig] = []
    for tname, traw in data.get("triggers", {}).items():
        triggers.append(_parse_trigger(tname, traw))

    # --- groups section ---
    groups: list[GroupConfig] = []
    for gname, graw in data.get("groups", {}).items():
        groups.append(_parse_group(gname, graw))

    return AppConfig(
        milter=milter,
        rdap=rdap,
        logging=logging_cfg,
        triggers=triggers,
        groups=groups,
    )

