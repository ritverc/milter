"""
Domain age check.

Queries an RDAP lookup service for the creation date of the sender's
domain and triggers if the domain is younger than a configurable
threshold.
"""

from __future__ import annotations

import asyncio
import logging
from email.message import Message
from typing import Any

from .base import BaseCheck, CheckResult
from ..rdap_client import RdapClient

logger = logging.getLogger(__name__)


class DomainAgeCheck(BaseCheck):
    """
    Trigger that fires when the sender's domain age is below a threshold.

    Parameters (from TOML ``params``):
        max_age_days    : int   — maximum age in days to consider "suspicious" (default 30).
        trusted_domains : list  — domains exempt from this check.
        tld_priorities  : dict  — optional TLD → extra score modifier.
    """

    check_type = "domain_age"

    def __init__(self, name: str, params: dict[str, Any], rdap: RdapClient) -> None:
        super().__init__(name, params)
        self.rdap = rdap
        self.max_age_days: int = int(self._param("max_age_days", 30))
        self.trusted_domains: set[str] = set(self._param("trusted_domains", []))
        self.tld_priorities: dict[str, int] = self._param("tld_priorities", {})

    def check(
        self,
        sender: str,
        sender_domain: str,
        subject: str,
        headers: dict[str, list[str]],
        message: Message,
    ) -> CheckResult:
        # Run the async RDAP query inside a sync context.
        # The milter callback runs in a thread, so we use asyncio.run()
        # only if there's no running loop; otherwise we run in a
        # separate thread.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                age_days = pool.submit(
                    asyncio.run, self.rdap.get_domain_age_days(sender_domain)
                ).result()
        else:
            age_days = asyncio.run(self.rdap.get_domain_age_days(sender_domain))

        if age_days is None:
            logger.info("Could not determine age for domain %s", sender_domain)
            return CheckResult(
                triggered=False,
                reason=f"Could not determine age for {sender_domain}",
                details={"domain": sender_domain, "age_days": None},
            )

        # Exempt trusted domains
        if sender_domain.lower() in {d.lower() for d in self.trusted_domains}:
            logger.debug("Domain %s is in trusted list, skipping", sender_domain)
            return CheckResult(
                triggered=False,
                reason=f"Trusted domain: {sender_domain}",
                details={"domain": sender_domain, "age_days": age_days, "trusted": True},
            )

        if age_days <= self.max_age_days:
            # Check TLD priority modifier
            tld = sender_domain.rsplit(".", 1)[-1].lower() if "." in sender_domain else ""
            tld_extra = self.tld_priorities.get(tld, 0)

            return CheckResult(
                triggered=True,
                reason=(
                    f"Domain {sender_domain} is {age_days} days old "
                    f"(threshold: {self.max_age_days})"
                ),
                details={
                    "domain": sender_domain,
                    "age_days": age_days,
                    "max_age_days": self.max_age_days,
                    "tld": tld,
                    "tld_priority_extra": tld_extra,
                },
            )

        return CheckResult(
            triggered=False,
            reason=f"Domain {sender_domain} is {age_days} days old (above threshold)",
            details={"domain": sender_domain, "age_days": age_days},
        )

