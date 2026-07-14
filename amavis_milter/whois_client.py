"""
Asynchronous WHOIS client for whois.nic.ru.

Parses the response to extract domain creation date and calculates
the domain's age in days. Results are cached in memory with a
configurable TTL.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

from amavis_milter.config import WhoisConfig

logger = logging.getLogger(__name__)

# Patterns for creation-date extraction from whois.nic.ru responses.
# The RU/CIS registry uses various date formats; we cover the common ones.
_CREATED_PATTERNS: list[re.Pattern[str]] = [
    # whois.nic.ru: "created:       2023.09.23" (YYYY.MM.DD — the actual format)
    re.compile(r"created:\s*(\d{4}\.\d{2}\.\d{2})", re.IGNORECASE),
    # whois.nic.ru alternate: "created:       2023-09-23" (YYYY-MM-DD)
    re.compile(r"created:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE),
    # Alternate: "Created On: 15.01.2023" (DD.MM.YYYY)
    re.compile(r"created(?:\s+on)?:\s*(\d{2}\.\d{2}\.\d{4})", re.IGNORECASE),
    # Generic: "Creation Date: 2023-01-15T12:00:00Z"
    re.compile(r"creation\s*date:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE),
    # "paid-till: 2024.10.01" (YYYY.MM.DD — used as proxy when created is absent)
    re.compile(r"paid-till:\s*(\d{4}\.\d{2}\.\d{2})", re.IGNORECASE),
    # "paid-till: 2024-10-01" (YYYY-MM-DD)
    re.compile(r"paid-till:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE),
]


def _parse_date(raw: str) -> Optional[datetime]:
    """Try to parse a date string into a datetime."""
    for fmt in ("%Y.%m.%d", "%Y-%m-%d", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class WhoisClient:
    """
    Async WHOIS client with in-memory caching.

    Parameters
    ----------
    config : WhoisConfig
        Connection and caching settings.
    """

    def __init__(self, config: WhoisConfig) -> None:
        self.config = config
        self._cache: dict[str, tuple[float, Optional[datetime]]] = {}
        self._semaphore = asyncio.Semaphore(10)  # limit concurrent queries

    # ---- public API ------------------------------------------------------

    async def get_domain_age_days(self, domain: str) -> Optional[int]:
        """
        Return the age of *domain* in whole days, or None on failure.

        Uses the in-memory cache first, then queries whois.nic.ru.
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
            logger.debug("WHOIS cache hit for %s", domain)
            return cached

        creation = await self._query(domain)
        self._write_cache(domain, creation)
        return creation

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
        # Evict oldest entries if the cache is too large
        if len(self._cache) >= self.config.cache_max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]
        self._cache[domain] = (time.monotonic(), creation)

    # ---- network ---------------------------------------------------------

    async def _query(self, domain: str) -> Optional[datetime]:
        """
        Perform a WHOIS query to whois.nic.ru and extract the creation date.
        """
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.config.server,
                        self.config.port,
                    ),
                    timeout=self.config.timeout,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                logger.warning("WHOIS connection to %s failed: %s", self.config.server, exc)
                return None

        try:
            writer.write((domain + "\r\n").encode("utf-8"))
            await writer.drain()

            chunks: list[bytes] = []
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=self.config.timeout)
                if not data:
                    break
                chunks.append(data)

            raw_response = b"".join(chunks).decode("utf-8", errors="replace")
        except (OSError, asyncio.TimeoutError) as exc:
            logger.warning("WHOIS read from %s failed: %s", self.config.server, exc)
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

        return self._extract_creation_date(raw_response)

    # ---- parsing ---------------------------------------------------------

    @staticmethod
    def _extract_creation_date(response: str) -> Optional[datetime]:
        """Extract the creation date from a WHOIS response text."""
        for pattern in _CREATED_PATTERNS:
            match = pattern.search(response)
            if match:
                return _parse_date(match.group(1))
        logger.debug("Could not extract creation date from WHOIS response")
        logger.debug(response)
        return None
