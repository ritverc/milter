#!/usr/bin/env python3
"""
Standalone test script for DomainAgeCheck (RDAP-based).

Usage:
    # Live RDAP test — queries who-dat.as93.net
    python test_domain_age.py live yandex.ru
    python test_domain_age.py live somedomain.xyz

    # Mock test — no network, uses fake RDAP responses
    python test_domain_age.py mock

    # Direct RDAP client test
    python test_domain_age.py rdap google.com
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import AsyncMock, patch

# ---------------------------------------------------------------------------
# Ensure the amavis_milter package is importable from the parent directory
# ---------------------------------------------------------------------------
sys.path.insert(0, ".")

from amavis_milter.checks.base import CheckResult
from amavis_milter.checks.domain_age import DomainAgeCheck
from amavis_milter.config import RdapConfig
from amavis_milter.rdap_client import RdapClient

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ===================================================================
# Mock RDAP responses (who-dat.as93.net normalised format)
# ===================================================================

MOCK_RDAP_OLD = {
    "query": "yandex.ru",
    "domain": "yandex.ru",
    "isRegistered": True,
    "registrar": {"name": "RU-CENTER-RU"},
    "status": ["REGISTERED", "DELEGATED", "VERIFIED"],
    "dates": {
        "created": "1997-09-23T09:45:07Z",
        "updated": None,
        "expires": "2026-09-30T21:00:00Z",
    },
}

MOCK_RDAP_YOUNG = {
    "query": "newproject.xyz",
    "domain": "newproject.xyz",
    "isRegistered": True,
    "registrar": {"name": "NAMECHEAP-INc"},
    "status": ["client transfer prohibited"],
    "dates": {
        "created": None,  # will be filled dynamically
        "updated": None,
        "expires": "2026-10-01T00:00:00Z",
    },
}

MOCK_RDAP_NOT_FOUND = {
    "query": "nonexistent12345.ru",
    "domain": "nonexistent12345.ru",
    "isRegistered": False,
    "dates": {
        "created": None,
        "updated": None,
        "expires": None,
    },
}

MOCK_RDAP_ERROR = {
    "error": {
        "code": "INVALID_DOMAIN",
        "message": "no valid public suffix",
        "query": "bad_domain",
    }
}

MOCK_RDAP_STANDARD_EVENTS = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2019-09-09T15:39:04Z"},
    ],
}


# ===================================================================
# Helpers
# ===================================================================

def _make_check(
    max_age_days: int = 30,
    trusted_domains: list[str] | None = None,
    tld_priorities: dict[str, int] | None = None,
    rdap: RdapClient | None = None,
) -> DomainAgeCheck:
    """Create a DomainAgeCheck with sensible defaults for testing."""
    if rdap is None:
        rdap = RdapClient(RdapConfig(service_url="https://who-dat.as93.net", timeout=10.0))
    params: dict[str, Any] = {"max_age_days": max_age_days}
    if trusted_domains is not None:
        params["trusted_domains"] = trusted_domains
    if tld_priorities is not None:
        params["tld_priorities"] = tld_priorities
    return DomainAgeCheck("test_domain_age", params, rdap)


def _print_result(domain: str, result: CheckResult) -> None:
    """Pretty-print a check result."""
    status = "⚠️  TRIGGERED" if result.triggered else "✅ OK"
    print(f"\n  Domain: {domain}")
    print(f"  Status: {status}")
    print(f"  Reason: {result.reason}")
    if result.details:
        for k, v in result.details.items():
            print(f"    {k}: {v}")


def _mock_raw_query(response: dict[str, Any]):
    """Return an async function that returns the given RDAP response."""
    async def _fake_query(self, domain: str):
        return RdapClient._extract_creation_date(response)
    return _fake_query


# ===================================================================
# Live test — real RDAP queries
# ===================================================================

def cmd_live(domains: list[str]) -> None:
    """Test with real RDAP queries to who-dat.as93.net."""
    rdap = RdapClient(RdapConfig(service_url="https://who-dat.as93.net", timeout=15.0))
    check = _make_check(max_age_days=30, rdap=rdap)

    for domain in domains:
        print(f"\n{'='*60}")
        print(f"Querying RDAP for: {domain}")
        print(f"{'='*60}")

        result = check.check(
            sender=f"user@{domain}",
            sender_domain=domain,
            subject="Test message",
            headers={},
            message=None,
        )
        _print_result(domain, result)

    # Show cache stats
    print(f"\nRDAP cache entries: {len(rdap._cache)}")


# ===================================================================
# Mock test — no network required
# ===================================================================

def cmd_mock() -> None:
    """Test with mock RDAP responses — no network required."""

    # --- Scenario 1: Old domain (should NOT trigger) ---
    print(f"\n{'='*60}")
    print("Scenario 1: Old domain — yandex.ru (created 1997)")
    print(f"{'='*60}")
    with patch.object(RdapClient, "_query", _mock_raw_query(MOCK_RDAP_OLD)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(max_age_days=30, rdap=rdap)
        result = check.check(
            sender="user@yandex.ru",
            sender_domain="yandex.ru",
            subject="Hello",
            headers={},
            message=None,
        )
        _print_result("yandex.ru", result)
        assert not result.triggered, "Old domain should not trigger"

    # --- Scenario 2: Young domain (5 days old — SHOULD trigger) ---
    print(f"\n{'='*60}")
    print("Scenario 2: Young domain — newproject.xyz (5 days old)")
    print(f"{'='*60}")
    five_days_ago = (datetime.now(tz=timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    young_resp = json.loads(json.dumps(MOCK_RDAP_YOUNG))
    young_resp["dates"]["created"] = five_days_ago
    with patch.object(RdapClient, "_query", _mock_raw_query(young_resp)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(max_age_days=30, rdap=rdap)
        result = check.check(
            sender="admin@newproject.xyz",
            sender_domain="newproject.xyz",
            subject="Special offer!",
            headers={},
            message=None,
        )
        _print_result("newproject.xyz", result)
        assert result.triggered, "Young domain should trigger"
        assert result.details["age_days"] <= 30

    # --- Scenario 3: Very young domain (1 day) with TLD priority ---
    print(f"\n{'='*60}")
    print("Scenario 3: Very young .xyz domain with TLD priority")
    print(f"{'='*60}")
    one_day_ago = (datetime.now(tz=timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    very_young_resp = json.loads(json.dumps(MOCK_RDAP_YOUNG))
    very_young_resp["dates"]["created"] = one_day_ago
    very_young_resp["domain"] = "scam.xyz"
    with patch.object(RdapClient, "_query", _mock_raw_query(very_young_resp)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(
            max_age_days=30,
            tld_priorities={"xyz": 2.0, "click": 2.5},
            rdap=rdap,
        )
        result = check.check(
            sender="info@scam.xyz",
            sender_domain="scam.xyz",
            subject="You won!",
            headers={},
            message=None,
        )
        _print_result("scam.xyz", result)
        assert result.triggered
        assert result.details["tld"] == "xyz"
        assert result.details["tld_priority_extra"] == 2.0

    # --- Scenario 4: Trusted domain (should NOT trigger even if young) ---
    print(f"\n{'='*60}")
    print("Scenario 4: Trusted domain — bypasses age check")
    print(f"{'='*60}")
    with patch.object(RdapClient, "_query", _mock_raw_query(very_young_resp)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(
            max_age_days=30,
            trusted_domains=["scam.xyz"],
            rdap=rdap,
        )
        result = check.check(
            sender="user@scam.xyz",
            sender_domain="scam.xyz",
            subject="Internal",
            headers={},
            message=None,
        )
        _print_result("scam.xyz (trusted)", result)
        assert not result.triggered, "Trusted domain should not trigger"
        assert result.details.get("trusted") is True

    # --- Scenario 5: Domain not registered ---
    print(f"\n{'='*60}")
    print("Scenario 5: Domain not registered")
    print(f"{'='*60}")
    with patch.object(RdapClient, "_query", _mock_raw_query(MOCK_RDAP_NOT_FOUND)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(max_age_days=30, rdap=rdap)
        result = check.check(
            sender="user@nonexistent12345.ru",
            sender_domain="nonexistent12345.ru",
            subject="Test",
            headers={},
            message=None,
        )
        _print_result("nonexistent12345.ru", result)
        assert not result.triggered, "Unregistered domain should not trigger"
        assert result.details["age_days"] is None

    # --- Scenario 6: RDAP error response ---
    print(f"\n{'='*60}")
    print("Scenario 6: RDAP error response (invalid domain)")
    print(f"{'='*60}")
    with patch.object(RdapClient, "_query", _mock_raw_query(MOCK_RDAP_ERROR)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(max_age_days=30, rdap=rdap)
        result = check.check(
            sender="user@bad_domain",
            sender_domain="bad_domain",
            subject="Test",
            headers={},
            message=None,
        )
        _print_result("bad_domain", result)
        assert not result.triggered, "RDAP error should not trigger"

    # --- Scenario 7: Custom threshold ---
    print(f"\n{'='*60}")
    print("Scenario 7: Custom threshold — max_age_days=7, domain 10 days old")
    print(f"{'='*60}")
    ten_days_ago = (datetime.now(tz=timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ten_day_resp = json.loads(json.dumps(MOCK_RDAP_YOUNG))
    ten_day_resp["dates"]["created"] = ten_days_ago
    with patch.object(RdapClient, "_query", _mock_raw_query(ten_day_resp)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(max_age_days=7, rdap=rdap)
        result = check.check(
            sender="admin@newproject.xyz",
            sender_domain="newproject.xyz",
            subject="Offer",
            headers={},
            message=None,
        )
        _print_result("newproject.xyz (threshold=7)", result)
        assert not result.triggered, "10-day domain with threshold=7 should not trigger"

    # --- Scenario 8: Standard RDAP events format (no who-dat normalisation) ---
    print(f"\n{'='*60}")
    print("Scenario 8: Standard RDAP events format (direct registry)")
    print(f"{'='*60}")
    with patch.object(RdapClient, "_query", _mock_raw_query(MOCK_RDAP_STANDARD_EVENTS)):
        rdap = RdapClient(RdapConfig())
        check = _make_check(max_age_days=30, rdap=rdap)
        result = check.check(
            sender="user@example.com",
            sender_domain="example.com",
            subject="Test",
            headers={},
            message=None,
        )
        _print_result("example.com", result)
        assert not result.triggered, "Old domain via standard RDAP events should not trigger"

    print(f"\n{'='*60}")
    print("✅ All mock scenarios passed!")
    print(f"{'='*60}")


# ===================================================================
# RDAP client test — direct query
# ===================================================================

def cmd_rdap(domain: str) -> None:
    """Test RDAP client directly — shows raw creation date and age."""
    rdap = RdapClient(RdapConfig(service_url="https://who-dat.as93.net", timeout=15.0))

    creation = asyncio.run(rdap.get_creation_date(domain))
    age = asyncio.run(rdap.get_domain_age_days(domain))
    registered = asyncio.run(rdap.is_registered(domain))

    print(f"Domain:        {domain}")
    print(f"Registered:    {registered}")
    print(f"Creation date: {creation}")
    print(f"Age (days):    {age}")


# ===================================================================
# Main
# ===================================================================

def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "live":
        if len(sys.argv) < 3:
            print("Usage: python test_domain_age.py live <domain> [domain2 ...]")
            sys.exit(1)
        cmd_live(sys.argv[2:])

    elif mode == "mock":
        cmd_mock()

    elif mode == "rdap":
        if len(sys.argv) < 3:
            print("Usage: python test_domain_age.py rdap <domain>")
            sys.exit(1)
        cmd_rdap(sys.argv[2])

    else:
        print(f"Unknown mode: {mode}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()

