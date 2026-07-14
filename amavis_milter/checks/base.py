"""
Base class for all check (trigger) implementations.

Every check receives the message context, performs its analysis,
and returns a CheckResult indicating whether the rule fired.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.message import Message
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a single check execution."""

    triggered: bool = False
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.triggered


class BaseCheck(ABC):
    """Abstract base for all trigger checks."""

    # Subclasses must set this to match the 'type' field in TOML triggers.
    check_type: str = ""

    def __init__(self, name: str, params: dict[str, Any]) -> None:
        self.name = name
        self.params = params
        self.logger = logging.getLogger(f"{self.__class__.__name__}({name})")

    @abstractmethod
    def check(
        self,
        sender: str,
        sender_domain: str,
        subject: str,
        headers: dict[str, list[str]],
        message: Message,
    ) -> CheckResult:
        """
        Execute the check against the given message context.

        Parameters
        ----------
        sender : str
            Full envelope sender address (e.g. "user@example.com").
        sender_domain : str
            Domain part of the sender.
        subject : str
            Decoded Subject header value.
        headers : dict[str, list[str]]
            All message headers (lowercased name → list of values).
        message : email.message.Message
            Full email message object for advanced inspection.

        Returns
        -------
        CheckResult
        """
        ...  # pragma: no cover

    def _param(self, key: str, default: Any = None) -> Any:
        """Convenience accessor for a parameter with default."""
        return self.params.get(key, default)
