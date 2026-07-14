"""
Rule engine that orchestrates trigger checks and group evaluation.

The engine:
  1. Runs individual triggers and collects results.
  2. Evaluates group rules (compound triggers) based on individual results.
  3. Produces a combined list of fired actions (header, score, subject prefix).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from email.message import Message
from typing import Any

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
