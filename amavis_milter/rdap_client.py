"""
Asynchronous RDAP client.

Queries an RDAP lookup service (default: who-dat.as93.net) for domain
metadata and extracts the creation date to calculate domain age.
Results are cached in memory with a configurable TTL.

The who-dat.as93.net service normalises RDAP responses from all TLD
registries into a consistent JSON format, so we get reliable
``dates.created`` fields for .ru, .com, .xyz, etc. without having
to handle each registry's quirks individually.

If the service is unavailable, the query returns None and the
domain_age check gracefully skips the trigger.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .config import RdapConfig

logger = logging.getLogger(__name__)


def _parse_iso_datetime(raw: str) -> Optional[datetime]:
    """
    Parse an ISO-8601 datetime string into a timezone-aware datetime.

    Handles formats like:
        2023-09-23T09:45:07Z
        2023-09-23T09:45:07+03:00
        2023-09-23
    """
    if not raw:
        return None

    # Try common ISO formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Last resort: try fromisoformat (Python 3.7+)
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass

    logger.debug("Cannot parse datetime: %s", raw)
    return None


class RdapClient:
    """
    Async RDAP client with in-memory caching.

    Uses an HTTP-based RDAP lookup service (who-dat.as93.net by default)
    that normalises RDAP responses across all TLD registries into a
    consistent JSON format with fields like ``dates.created``.

    Parameters
    ----------
    config : RdapConfig
        Service URL, HTTP timeout, and caching settings.
    """

    def __init__(self, config: RdapConfig) -> None:
        self.config = config
        self._cache: dict[str, tuple[float, Optional[datetime]]] = {}
        self._semaphore = asyncio.Semaphore(config.max_concurrent)

    # ---- public API ------------------------------------------------------

    async def get_domain_age_days(self, domain: str) -> Optional[int]:
        """
        Return the age of *domain* in whole days, or ``None`` on failure.

        Uses the in-memory cache first, then queries the RDAP service.
        """
        creation = await self.get_creation_date(domain)
        if creation is None:
            return None
        now = datetime.now(tz=timezone.utc)
        delta = now - creation
        return delta.days

    async def get_creation_date(self, domain: str) -> Optional[datetime]:
        """
        Return the creation date of *domain*, using cache when possible.
        """
        cached = self._read_cache(domain)
        if cached is not None:
            logger.debug("RDAP cache hit for %s", domain)
            return cached

        creation = await self._query(domain)
        self._write_cache(domain, creation)
        return creation

    async def is_registered(self, domain: str) -> Optional[bool]:
        """
        Check if *domain* is registered. Returns ``None`` on failure.
        """
        data = await self._raw_query(domain)
        if data is None:
            return None
        return data.get("isRegistered")

    def clear_cache(self) -> None:
        """Drop all cached entries."""
        self._cache.clear()

    # ---- cache -----------------------------------------------------------

    def _read_cache(self, domain: str) -> Optional[datetime]:
        entry = self._cache.get(domain)
        if entry is None:
            return None
        ts, creation = entry
        if time.monotonic() - ts > self.config.cache_ttl:
            del self._cache[domain]
            return None
        return creation

    def _write_cache(self, domain: str, creation: Optional[datetime]) -> None:
        if len(self._cache) >= self.config.cache_max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]
        self._cache[domain] = (time.monotonic(), creation)

    # ---- network ---------------------------------------------------------

    async def _raw_query(self, domain: str) -> Optional[dict[str, Any]]:
        """
        Perform an RDAP query and return the parsed JSON, or None on failure.
        """
        url = f"{self.config.service_url.rstrip('/')}/{domain}"
        async with self._semaphore:
            try:
                import urllib.request
                import urllib.error

                req = urllib.request.Request(
                    url,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "amavis-milter/1.0",
                    },
                )
                loop = asyncio.get_running_loop()
                response_data = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=self.config.timeout)),
                    timeout=self.config.timeout + 2.0,
                )
                body = response_data.read().decode("utf-8", errors="replace")
                data: dict[str, Any] = json.loads(body)
                return data
            except json.JSONDecodeError as exc:
                logger.warning("RDAP response for %s is not valid JSON: %s", domain, exc)
                return None
            except Exception as exc:  # noqa: BLE001
                logger.warning("RDAP query for %s failed: %s", domain, exc)
                return None

    async def _query(self, domain: str) -> Optional[datetime]:
        """
        Query the RDAP service and extract the creation date.
        """
        data = await self._raw_query(domain)
        if data is None:
            return None

        # Handle error responses
        if "error" in data:
            err = data["error"]
            logger.debug(
                "RDAP error for %s: code=%s message=%s",
                domain,
                err.get("code"),
                err.get("message"),
            )
            return None

        # Not registered — no creation date
        if data.get("isRegistered") is False:
            logger.debug("RDAP: domain %s is not registered", domain)
            return None

        return self._extract_creation_date(data)

    # ---- parsing ---------------------------------------------------------

    @staticmethod
    def _extract_creation_date(data: dict[str, Any]) -> Optional[datetime]:
        """
        Extract the creation date from a normalised RDAP response.

        The who-dat service returns ``dates.created`` in ISO-8601.
        As a fallback, also check standard RDAP ``events`` array.
        """
        # 1. who-dat normalised format: data.dates.created
        dates = data.get("dates")
        if isinstance(dates, dict):
            raw_created = dates.get("created")
            if raw_created:
                result = _parse_iso_datetime(raw_created)
                if result:
                    return result

        # 2. Standard RDAP: data.events[eventAction=registration]
        events = data.get("events")
        if isinstance(events, list):
            for event in events:
                if event.get("eventAction") in ("registration", "created"):
                    raw_date = event.get("eventDate")
                    if raw_date:
                        result = _parse_iso_datetime(raw_date)
                        if result:
                            return result

        logger.debug("Could not extract creation date from RDAP response")
        return None

