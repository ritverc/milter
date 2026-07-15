#!/usr/bin/env python3
"""
Standalone test module for FuzzyDomainCheck.

Covers:
  - The reported bug: trusted_domains must also cover subdomains, so that
    mail sent from ``mail.abcd.com`` is NOT flagged as a lookalike of a
    sibling domain ``abcd.kz`` when ``abcd.com`` is trusted.
  - History semantics: a flagged lookalike is never recorded; a non-flagged
    sender (including trusted ones and short domains) IS recorded.
  - Similarity threshold behaviour (fire / no-fire boundary).
  - same_tld_skip behaviour.
  - min_length guard.
  - known_domains vs trusted_domains distinction.
  - Persistence of history to a JSON file.

Usage:
    # Run as a plain script (uses the assertions below, no pytest needed):
    python test_fuzzy_domain.py

    # Or with pytest (recommended):
    pytest test_fuzzy_domain.py -v

The tests do not touch the network and do not require the Levenshtein C
extension (the check falls back to difflib.SequenceMatcher).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Any

# ---------------------------------------------------------------------------
# Ensure the amavis_milter package is importable from the parent directory
# ---------------------------------------------------------------------------
sys.path.insert(0, ".")

from amavis_milter.checks.base import CheckResult  # noqa: E402
from amavis_milter.checks.fuzzy_domain import (  # noqa: E402
    FuzzyDomainCheck,
    _domain_similarity,
    _levenshtein_ratio,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_check(**overrides: Any) -> FuzzyDomainCheck:
    """Build a FuzzyDomainCheck with sensible defaults + overrides."""
    params: dict[str, Any] = {
        "similarity_threshold": 0.75,
        "min_length": 4,
        "known_domains": ["gmail.com", "yandex.ru", "abcd.com", "abcd.kz"],
        "trusted_domains": ["gmail.com", "abcd.com", "abcd.kz"],
        "same_tld_skip": False,
        "history_file": "",  # no persistence by default
        "history_max_entries": 50000,
    }
    params.update(overrides)
    return FuzzyDomainCheck("fuzzy_domain", params)


def _run(check: FuzzyDomainCheck, sender_domain: str) -> CheckResult:
    """Invoke check() with a synthetic message context."""
    return check.check(
        sender=f"user@{sender_domain}",
        sender_domain=sender_domain,
        subject="",
        headers={},
        message=None,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Test 1: the reported bug — subdomains of trusted domains are trusted
# ---------------------------------------------------------------------------

def test_subdomain_of_trusted_is_trusted() -> None:
    """
    Regression for the user-reported bug.

    abcd.com and abcd.kz are both in known_domains AND trusted_domains.
    Mail from abcd.com / abcd.kz (exact) must NOT fire.
    Mail from mail.abcd.com / smtp.abcd.kz / gateway.mail.abcd.com
    (subdomains) must ALSO NOT fire.
    """
    check = _make_check()

    # Exact trusted domains — must not fire.
    for sd in ("abcd.com", "abcd.kz"):
        r = _run(check, sd)
        assert not r.triggered, (
            f"Exact trusted domain {sd!r} unexpectedly fired: {r.reason}"
        )
        assert "trusted" in r.reason.lower(), (
            f"Expected 'trusted' in reason for {sd!r}, got: {r.reason!r}"
        )

    # Subdomains of trusted domains — must NOT fire either.
    for sd in (
        "mail.abcd.com",
        "smtp.abcd.kz",
        "gateway.mail.abcd.com",
        "MAIL.ABCD.COM",            # case-insensitive
        "mail.Abcd.Com",
    ):
        r = _run(check, sd)
        assert not r.triggered, (
            f"Subdomain {sd!r} of a trusted domain unexpectedly fired: "
            f"{r.reason}"
        )
        assert "trusted" in r.reason.lower(), (
            f"Expected 'trusted' in reason for subdomain {sd!r}, "
            f"got: {r.reason!r}"
        )


# ---------------------------------------------------------------------------
# Test 2: a lookalike that is NOT trusted must still fire
# ---------------------------------------------------------------------------

def test_typosquat_not_trusted_fires() -> None:
    """gmai.com (not trusted) is similar to gmail.com (known) → must fire."""
    check = _make_check()
    r = _run(check, "gmai.com")
    assert r.triggered, (
        f"gmai.com should be flagged as similar to gmail.com: {r.reason}"
    )
    assert "gmail.com" in r.reason, (
        f"Expected match against gmail.com, got: {r.reason!r}"
    )


def test_typosquat_of_sibling_domain_fires() -> None:
    """
    A typosquat of a sibling domain (e.g. abcd.cz mimicking abcd.com/abcd.kz)
    that is NOT in trusted_domains must still fire.
    """
    check = _make_check()
    # abcd.cz is NOT trusted, NOT known — it should match abcd.com/abcd.kz.
    r = _run(check, "abcd.cz")
    assert r.triggered, (
        f"abcd.cz should be flagged as similar to abcd.com/abcd.kz: {r.reason}"
    )


# ---------------------------------------------------------------------------
# Test 3: a domain similar to a trusted-but-not-itself domain fires
# ---------------------------------------------------------------------------

def test_lookalike_suffix_does_not_match_trusted() -> None:
    """
    'evilabcd.com' must NOT be treated as a subdomain of trusted 'abcd.com'
    (the leading-dot rule). It should be compared normally and, if similar,
    fire.
    """
    check = _make_check()
    # evilabcd.com ends with 'abcd.com' but NOT '.abcd.com' → not trusted.
    # Its SLD 'evilabcd' vs 'abcd' is similar enough to fire at default 0.75?
    # Let's assert at least that it is NOT classified as trusted.
    r = _run(check, "evilabcd.com")
    assert "trusted" not in r.reason.lower(), (
        f"evilabcd.com must NOT be considered a subdomain of abcd.com: "
        f"{r.reason!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: history semantics — flagged domains are never recorded
# ---------------------------------------------------------------------------

def test_flagged_domain_not_recorded_in_history() -> None:
    """When the check fires, the sender domain must NOT enter history."""
    check = _make_check()
    r = _run(check, "gmai.com")  # fires
    assert r.triggered
    assert "gmai.com" not in check._history, (
        "Flagged typosquat gmai.com must NOT be recorded in history"
    )


def test_non_flagged_domain_recorded_in_history() -> None:
    """When the check does NOT fire, the sender domain MUST enter history."""
    check = _make_check(known_domains=["gmail.com"])  # only gmail as reference
    r = _run(check, "example.org")  # benign, not similar to gmail.com
    assert not r.triggered
    assert "example.org" in check._history, (
        "Benign domain example.org MUST be recorded in history"
    )


def test_trusted_domain_recorded_in_history() -> None:
    """
    A trusted sender domain does not fire, so it IS recorded in history.
    (This is fine — it's a legitimate domain and can serve as a reference.)
    """
    check = _make_check()
    r = _run(check, "abcd.com")
    assert not r.triggered
    assert "abcd.com" in check._history, (
        "Trusted domain abcd.com (non-triggered) should be recorded in history"
    )


def test_subdomain_of_trusted_recorded_in_history() -> None:
    """A trusted subdomain (non-triggered) is also recorded in history."""
    check = _make_check()
    r = _run(check, "mail.abcd.com")
    assert not r.triggered
    assert "mail.abcd.com" in check._history


def test_short_domain_recorded_in_history() -> None:
    """A too-short domain does not fire, so it is recorded in history."""
    check = _make_check(min_length=10)
    r = _run(check, "a.b")  # len 3 < 10
    assert not r.triggered
    assert "a.b" in check._history


# ---------------------------------------------------------------------------
# Test 5: history persistence
# ---------------------------------------------------------------------------

def test_history_persistence_roundtrip() -> None:
    """Flagged domains are absent from the persisted history file;
    benign domains are present after reload."""
    tmpdir = tempfile.mkdtemp()
    hist = os.path.join(tmpdir, "domain_history.json")

    check1 = _make_check(history_file=hist, known_domains=["gmail.com"])
    _run(check1, "gmai.com")       # fires → NOT recorded
    _run(check1, "example.org")    # benign → recorded
    _run(check1, "abcd.com")       # trusted → recorded

    # File must exist and contain only non-flagged domains.
    assert os.path.isfile(hist), "History file was not created"
    data = json.loads(open(hist, encoding="utf-8").read())
    assert "gmai.com" not in data, (
        "Flagged gmai.com must NOT be in persisted history"
    )
    assert "example.org" in data
    assert "abcd.com" in data

    # Reload into a fresh check — same invariants hold.
    check2 = _make_check(history_file=hist, known_domains=["gmail.com"])
    assert "gmai.com" not in check2._history
    assert "example.org" in check2._history
    assert "abcd.com" in check2._history


# ---------------------------------------------------------------------------
# Test 6: similarity threshold boundary
# ---------------------------------------------------------------------------

def test_high_similarity_fires() -> None:
    """Two very similar domains cross the threshold → fire."""
    check = _make_check(
        similarity_threshold=0.75,
        known_domains=["gmail.com"],
        trusted_domains=[],
    )
    # gmai.com vs gmail.com: SLD 'gmai' vs 'gmail' is very high.
    r = _run(check, "gmai.com")
    assert r.triggered


def test_low_similarity_does_not_fire() -> None:
    """Disjoint domains stay below the threshold → no fire."""
    check = _make_check(
        similarity_threshold=0.75,
        known_domains=["gmail.com"],
        trusted_domains=[],
    )
    r = _run(check, "example.org")
    assert not r.triggered
    assert r.details.get("similarity", 1.0) < 0.75


# ---------------------------------------------------------------------------
# Test 7: min_length guard
# ---------------------------------------------------------------------------

def test_min_length_guard() -> None:
    """Domains shorter than min_length do not fire and are recorded."""
    check = _make_check(min_length=8, known_domains=["gmail.com"])
    r = _run(check, "ab.co")  # len 5 < 8
    assert not r.triggered
    assert "too short" in r.reason.lower()
    assert "ab.co" in check._history


# ---------------------------------------------------------------------------
# Test 8: same_tld_skip
# ---------------------------------------------------------------------------

def test_same_tld_skip_suppresses_match() -> None:
    """
    With same_tld_skip=true, references sharing the sender's TLD are skipped.
    A typosquat in the same TLD that would otherwise fire is therefore not
    flagged (reduces false positives at the cost of missed same-TLD typosquats).
    """
    check = _make_check(
        same_tld_skip=True,
        known_domains=["yandex.ru"],
        trusted_domains=[],
        similarity_threshold=0.75,
    )
    # send 'yandx.ru' — similar to yandex.ru, same TLD .ru → skipped.
    r = _run(check, "yandx.ru")
    assert not r.triggered, (
        f"With same_tld_skip, same-TLD match should be skipped: {r.reason}"
    )


def test_same_tld_skip_allows_cross_tld_match() -> None:
    """With same_tld_skip=true, a cross-TLD typosquat still fires."""
    check = _make_check(
        same_tld_skip=True,
        known_domains=["gmail.com"],
        trusted_domains=[],
        similarity_threshold=0.75,
    )
    # gmai.ru vs gmail.com — different TLD, still compared.
    # SLD 'gmai' vs 'gmail' is very similar → should fire.
    r = _run(check, "gmai.ru")
    assert r.triggered, (
        f"Cross-TLD typosquat should fire even with same_tld_skip: {r.reason}"
    )


# ---------------------------------------------------------------------------
# Test 9: known_domains vs trusted_domains distinction
# ---------------------------------------------------------------------------

def test_known_domains_not_an_exemption() -> None:
    """
    Listing a domain in known_domains does NOT exempt it from being flagged
    when it is the SENDER — only trusted_domains does that.
    Here 'gmail.com' is in known_domains but NOT trusted_domains, and a
    typosquat 'gmai.com' (sender) must still fire against it.
    """
    check = _make_check(
        known_domains=["gmail.com"],
        trusted_domains=[],  # nothing trusted
    )
    r = _run(check, "gmai.com")
    assert r.triggered


def test_sender_in_known_but_not_trusted_is_compared() -> None:
    """
    If the sender's domain is itself in known_domains but NOT in
    trusted_domains, it is still compared against the OTHER references
    (it is discarded from references via the .discard(self) line, so it
    won't match itself, but it can match a sibling).
    """
    check = _make_check(
        known_domains=["abcd.com", "abcd.kz"],
        trusted_domains=[],  # abcd.com NOT trusted on purpose
        similarity_threshold=0.75,
    )
    # abcd.com (sender) vs abcd.kz (reference) — similarity ~0.88 → fires.
    r = _run(check, "abcd.com")
    assert r.triggered, (
        f"abcd.com not trusted should fire against abcd.kz: {r.reason}"
    )


# ---------------------------------------------------------------------------
# Test 10: similarity helper sanity
# ---------------------------------------------------------------------------

def test_identical_domains_similarity_is_one() -> None:
    assert _domain_similarity("gmail.com", "gmail.com") == 1.0


def test_siblings_have_high_similarity() -> None:
    s = _domain_similarity("abcd.com", "abcd.kz")
    assert s >= 0.75, f"abcd.com vs abcd.kz expected >=0.75, got {s}"


def test_disjoint_domains_have_low_similarity() -> None:
    s = _domain_similarity("gmail.com", "example.org")
    assert s < 0.5, f"gmail.com vs example.org expected <0.5, got {s}"


def test_levenshtein_ratio_identical() -> None:
    assert _levenshtein_ratio("abc", "abc") == 1.0


# ---------------------------------------------------------------------------
# CLI runner — allows `python test_fuzzy_domain.py` without pytest
# ---------------------------------------------------------------------------

def _run_all() -> int:
    """Discover and run all test_* functions in this module."""
    module = sys.modules[__name__]
    tests = sorted(
        name for name in dir(module)
        if name.startswith("test_") and callable(getattr(module, name))
    )
    passed = 0
    failed = 0
    for name in tests:
        func = getattr(module, name)
        try:
            func()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"  PASS  {name}")
    total = passed + failed
    print(f"\n{passed}/{total} tests passed, {failed} failed.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_run_all())
