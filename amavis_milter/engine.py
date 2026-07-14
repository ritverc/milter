"""
Rule engine that orchestrates trigger checks and group evaluation.

The engine:
  1. Runs individual triggers and collects results.
  2. Evaluates group rules (compound triggers) based on individual results.
  3. Produces a combined list of fired actions (header, score, subject prefix).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from email.message import Message
from typing import Optional

from amavis_milter.checks.base import BaseCheck, CheckResult
from amavis_milter.config import ActionConfig, AppConfig, GroupConfig, TriggerConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action — what to do when a rule fires
# ---------------------------------------------------------------------------

@dataclass
class FiredAction:
    """Represents a concrete action to be applied to the message."""

    source: str  # trigger name or group name
    action: ActionConfig
    result: CheckResult


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Central engine that manages triggers and groups, runs checks,
    and returns the aggregate set of actions.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._checks: dict[str, BaseCheck] = {}
        self._trigger_configs: dict[str, TriggerConfig] = {}
        self._group_configs: dict[str, GroupConfig] = {}
        self._register_triggers()
        self._prefix_strip_re: Optional[re.Pattern[str]] = self._build_prefix_strip_re()

    # ---- registration ----------------------------------------------------

    def register_check(self, check: BaseCheck) -> None:
        """Register an instantiated check object."""
        self._checks[check.name] = check

    def _register_triggers(self) -> None:
        """Index trigger and group configs for fast lookup."""
        for tc in self.config.triggers:
            self._trigger_configs[tc.name] = tc
        for gc in self.config.groups:
            self._group_configs[gc.name] = gc

    # ---- evaluation ------------------------------------------------------

    def evaluate(
        self,
        sender: str,
        sender_domain: str,
        subject: str,
        headers: dict[str, list[str]],
        message: Message,
    ) -> list[FiredAction]:
        """
        Run all enabled triggers and groups, return fired actions.
        """
        fired: list[FiredAction] = []

        # 1. Run individual triggers
        trigger_results: dict[str, CheckResult] = {}
        for tc in self.config.triggers:
            if not tc.enabled:
                continue
            check = self._checks.get(tc.name)
            if check is None:
                logger.warning("Trigger '%s' has no registered check implementation", tc.name)
                continue
            try:
                result = check.check(sender, sender_domain, subject, headers, message)
                trigger_results[tc.name] = result
                if result:
                    logger.info(
                        "Trigger '%s' fired: %s", tc.name, result.reason,
                    )
                    fired.append(FiredAction(source=tc.name, action=tc.action, result=result))
                else:
                    logger.debug("Trigger '%s' did not fire", tc.name)
            except Exception:
                logger.exception("Error running trigger '%s'", tc.name)

        # 2. Evaluate groups
        for gc in self.config.groups:
            if not gc.enabled:
                continue
            group_fired = self._evaluate_group(gc, trigger_results)
            if group_fired:
                logger.info("Group '%s' fired", gc.name)
                fired.append(
                    FiredAction(
                        source=gc.name,
                        action=gc.action,
                        result=CheckResult(
                            triggered=True,
                            reason=f"Group '{gc.name}' condition met",
                            details={"mode": gc.mode, "triggers": gc.triggers},
                        ),
                    )
                )

        return fired

    def _evaluate_group(
        self, group: GroupConfig, results: dict[str, CheckResult]
    ) -> bool:
        """Evaluate a single group based on individual trigger results."""
        if not group.triggers:
            return False

        triggered_list = [
            results.get(t, CheckResult(triggered=False))
            for t in group.triggers
        ]

        if group.mode == "all":
            return all(r.triggered for r in triggered_list)
        elif group.mode == "any":
            return any(r.triggered for r in triggered_list)
        elif group.mode == "majority":
            count = sum(1 for r in triggered_list if r.triggered)
            return count > len(triggered_list) / 2
        else:
            logger.warning("Unknown group mode '%s' for group '%s'", group.mode, group.name)
            return False

    # ---- convenience -----------------------------------------------------

    def get_total_spam_increase(self, actions: list[FiredAction]) -> float:
        """Calculate the total spam score increase from all fired actions."""
        return sum(a.action.spam_score_increase for a in actions)

    def get_subject_prefix(self, actions: list[FiredAction]) -> str:
        """Build a combined subject prefix from all fired actions that have one."""
        prefixes = [a.action.subject_prefix for a in actions if a.action.subject_prefix]
        return " ".join(prefixes)

    # ---- subject prefix deduplication -----------------------------------

    @property
    def known_prefixes(self) -> list[str]:
        """
        Return the unique, non-empty ``subject_prefix`` values declared by
        any trigger or group in the configuration (regardless of whether the
        trigger/group is enabled).

        These are the prefixes the milter itself may prepend to a Subject.
        They are used to detect and strip pre-existing prefixes so that a
        re-processed message does not accumulate duplicates such as
        ``[FAKE-REPLY] [FAKE-REPLY] Hello``.
        """
        prefixes: set[str] = set()
        for tc in self.config.triggers:
            if tc.action.subject_prefix:
                prefixes.add(tc.action.subject_prefix)
        for gc in self.config.groups:
            if gc.action.subject_prefix:
                prefixes.add(gc.action.subject_prefix)
        # Sort by length, descending, so that a shorter prefix cannot match
        # inside a longer one when both share a common start.
        return sorted(prefixes, key=len, reverse=True)

    def _build_prefix_strip_re(self) -> Optional[re.Pattern[str]]:
        """
        Compile a regex that matches a single known prefix at the start of a
        Subject, together with any surrounding whitespace.

        Returns ``None`` when no prefixes are configured (nothing to strip).
        """
        prefixes = self.known_prefixes
        if not prefixes:
            return None
        escaped = [re.escape(p) for p in prefixes]
        # Anchored at start; consumes leading whitespace, the prefix, and the
        # trailing whitespace so consecutive prefixes are fully cleared.
        return re.compile(r"^\s*(?:" + "|".join(escaped) + r")\s*")

    def has_known_prefixes(self) -> bool:
        """Whether any subject prefix is configured (and thus strippable)."""
        return self._prefix_strip_re is not None

    def strip_known_prefixes(self, subject: str) -> str:
        """
        Remove every known milter prefix that leads *subject*.
        Prefixes are stripped repeatedly from the front of the string so that
        sequences like ``[FAKE-REPLY] [YOUNG-DOMAIN] Hello`` collapse to
        ``Hello``. Behaviour is controlled by the
        ``milter.strip_existing_prefixes`` configuration flag: when disabled
        the subject is returned unchanged.

        Parameters
        ----------
        subject : str
            The decoded Subject header value.

        Returns
        -------
        str
            The subject with leading known prefixes (and their surrounding
            whitespace) removed.
        """
        if not self.config.milter.strip_existing_prefixes:
            return subject
        pattern = self._prefix_strip_re
        if not subject or pattern is None:
            return subject
        # Repeatedly remove one leading prefix until none remains. Each
        # iteration strictly shortens the string (prefixes are non-empty), so
        # the loop is guaranteed to terminate.
        while True:
            new_subject = pattern.sub("", subject, count=1)
            if new_subject == subject:
                break
            subject = new_subject
        return subject
