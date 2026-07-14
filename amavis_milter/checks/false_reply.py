"""
False reply check.

Detects emails with a "Re:" / "Fw:" prefix in the Subject but with
a missing, empty, or invalid In-Reply-To / References header — a
common tactic in spam to make messages appear as replies.
"""

from __future__ import annotations

import logging
import re
from email.message import Message
from typing import Any

from amavis_milter.checks.base import BaseCheck, CheckResult

logger = logging.getLogger(__name__)


class FalseReplyCheck(BaseCheck):
    """
    Trigger that fires when the subject looks like a reply/forward
    but the message lacks a valid In-Reply-To or References header.

    Parameters (from TOML ``params``):
        reply_prefixes    : list — subject prefixes to consider (default ["Re:", "RE:", "Fw:", "FW:"]).
        check_in_reply_to : bool — whether to check In-Reply-To header (default True).
        check_references  : bool — whether to check References header (default True).
    """

    check_type = "false_reply"

    def __init__(self, name: str, params: dict[str, Any]) -> None:
        super().__init__(name, params)
        self.reply_prefixes: list[str] = self._param(
            "reply_prefixes", ["Re:", "RE:", "Fw:", "FW:"]
        )
        self.check_in_reply_to: bool = self._param("check_in_reply_to", True)
        self.check_references: bool = self._param("check_references", True)

        # Build a regex that matches any configured prefix at the start of the subject
        escaped = [re.escape(p) for p in self.reply_prefixes]
        self._prefix_re = re.compile(
            r"^\s*(" + "|".join(escaped) + r")\s*",
            re.IGNORECASE,
        )

    def check(
        self,
        sender: str,
        sender_domain: str,
        subject: str,
        headers: dict[str, list[str]],
        message: Message,
    ) -> CheckResult:
        # 1. Does the subject have a reply/forward prefix?
        match = self._prefix_re.match(subject)
        if not match:
            return CheckResult(
                triggered=False,
                reason="Subject does not start with a reply/forward prefix",
            )

        detected_prefix = match.group(1)

        # 2. Is there a valid In-Reply-To?
        has_valid_in_reply_to = False
        if self.check_in_reply_to:
            in_reply_to_values = headers.get("in-reply-to", [])
            has_valid_in_reply_to = self._has_valid_header(in_reply_to_values)

        # 3. Is there a valid References?
        has_valid_references = False
        if self.check_references:
            references_values = headers.get("references", [])
            has_valid_references = self._has_valid_header(references_values)

        # 4. If both are missing/invalid → false reply
        if not has_valid_in_reply_to and not has_valid_references:
            return CheckResult(
                triggered=True,
                reason=(
                    f"Subject starts with '{detected_prefix}' but lacks valid "
                    f"In-Reply-To and References headers"
                ),
                details={
                    "detected_prefix": detected_prefix,
                    "in_reply_to_present": bool(headers.get("in-reply-to")),
                    "in_reply_to_valid": has_valid_in_reply_to,
                    "references_present": bool(headers.get("references")),
                    "references_valid": has_valid_references,
                },
            )

        return CheckResult(
            triggered=False,
            reason=(
                f"Subject starts with '{detected_prefix}' and has valid "
                f"reply threading headers"
            ),
            details={
                "detected_prefix": detected_prefix,
                "in_reply_to_valid": has_valid_in_reply_to,
                "references_valid": has_valid_references,
            },
        )

    @staticmethod
    def _has_valid_header(values: list[str]) -> bool:
        """
        Check that at least one value looks like a valid Message-ID.

        A valid Message-ID typically looks like <something@domain>.
        """
        msgid_re = re.compile(r"<[^>]+>")
        for val in values:
            stripped = val.strip()
            if stripped and msgid_re.search(stripped):
                return True
        return False
