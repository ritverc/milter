"""
Fuzzy domain similarity check.

Compares the sender's domain against a set of known/seen domains
using Levenshtein distance and a custom similarity metric.
Triggers when the similarity is above a threshold, suggesting
typosquatting or lookalike domain abuse.
"""

from __future__ import annotations

import json
import logging
import os
from difflib import SequenceMatcher
from email.message import Message
from pathlib import Path
from typing import Any

from amavis_milter.checks.base import BaseCheck, CheckResult

logger = logging.getLogger(__name__)


def _levenshtein_ratio(s1: str, s2: str) -> float:
    """
    Compute a normalised similarity ratio using Levenshtein distance.

    Falls back to difflib.SequenceMatcher if the Levenshtein C
    extension is not available.
    """
    try:
        from Levenshtein import ratio  # type: ignore[import-untyped]
        return ratio(s1.lower(), s2.lower())
    except ImportError:
        return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


def _domain_similarity(domain: str, reference: str) -> float:
    """
    Compute similarity between two domain names.

    We compare the second-level domain (SLD) part primarily,
    but also consider the full domain for more precise matching.
    """
    def _sld(d: str) -> str:
        """Extract second-level domain (e.g. 'example' from 'mail.example.com')."""
        parts = d.lower().split(".")
        return parts[-2] if len(parts) >= 2 else parts[0]

    sld_sim = _levenshtein_ratio(_sld(domain), _sld(reference))
    full_sim = _levenshtein_ratio(domain.lower(), reference.lower())

    # Weight: SLD similarity is more important
    return 0.65 * sld_sim + 0.35 * full_sim


class FuzzyDomainCheck(BaseCheck):
    """
    Trigger that fires when the sender's domain closely resembles a
    known / previously seen domain, suggesting typosquatting.

    Parameters (from TOML ``params``):
        similarity_threshold : float — minimum similarity to trigger (0..1, default 0.75).
        min_length           : int   — minimum domain length to compare (default 4).
        known_domains        : list  — reference targets: legitimate domains compared
                                       AGAINST the sender's domain. NOT an exemption
                                       list; it is the set of "victims" whose
                                       typosquats we want to catch.
        trusted_domains      : list  — sender-domain whitelist: if the sender's
                                       domain itself is here, the check is skipped
                                       entirely (never flagged), even if a similar
                                       typosquat is already in history. Subdomains
                                       of a trusted domain are also trusted
                                       (e.g. trusted "abcd.com" covers
                                       "mail.abcd.com").
        same_tld_skip        : bool  — skip references whose TLD matches the
                                       sender's TLD (default False, reduces FP).
        history_file         : str   — path to JSON file with dynamically collected
                                       domains (only NON-flagged senders are recorded;
                                       see below).
        history_max_entries  : int   — max entries to keep in history (default 50000).

    History semantics
    -----------------
    The sender's domain is appended to ``history`` ONLY when the check does
    NOT fire. A domain flagged as a lookalike is intentionally excluded, so
    that detected typosquats never become references for future comparisons
    (which would pollute the reference set and could mask or cascade into
    future detections).
    """

    check_type = "fuzzy_domain"

    def __init__(self, name: str, params: dict[str, Any]) -> None:
        super().__init__(name, params)
        self.similarity_threshold: float = float(self._param("similarity_threshold", 0.75))
        self.min_length: int = int(self._param("min_length", 4))
        self.known_domains: list[str] = {
            d.lower() for d in self._param("known_domains", [])
        }
        # Normalise trusted domains to lowercase once for fast, case-insensitive
        # comparison (including subdomain matching — see _is_trusted).
        self.trusted_domains: set[str] = {
            d.lower() for d in self._param("trusted_domains", [])
        }
        logger.debug("Configured trusted domains: %s", self.trusted_domains)
        logger.debug("Known domains: %s", self.known_domains)
        self.same_tld_skip: bool = self._param("same_tld_skip", False)
        self.history_file: str = self._param("history_file", "")
        self.history_max_entries: int = int(self._param("history_max_entries", 50000))
        self._history: set[str] = set()

        # Load persistent history
        if self.history_file:
            self._load_history()

    # ---- public API ------------------------------------------------------

    def _is_trusted(self, sender_domain: str) -> bool:
        """
        Return True if *sender_domain* is trusted and must skip the fuzzy check.

        A domain is trusted when it is EITHER:
          - exactly listed in ``trusted_domains`` (case-insensitive), OR
          - a subdomain of a listed trusted domain. For example, when
            ``abcd.com`` is trusted, ``mail.abcd.com`` and
            ``gateway.mail.abcd.com`` are trusted too — they belong to the
            same organisation and must not be flagged as lookalikes of a
            sibling domain (e.g. ``abcd.kz``).

        The subdomain rule prevents false positives where an organisation
        that legitimately owns both ``abcd.com`` and ``abcd.kz`` sends mail
        from ``mail.abcd.com``: without this rule the SLD-based similarity
        (which compares the ``abcd`` part) would match ``abcd.kz`` and
        trigger a false lookalike alert.
        """
        sd = sender_domain.lower()
#        logger.debug("Checking sender domain ", sd, " against list of")
#        logger.debug("trusted domains:", self.trusted_domains)
        if sd in self.trusted_domains:
            return True
        # Subdomain match: any deeper name ending with ".<trusted>".
        # The leading dot guarantees "evilabcd.com" does NOT match "abcd.com".
        for trusted in self.trusted_domains:
            if sd.endswith("." + trusted):
                return True
        return False

    def check(
        self,
        sender: str,
        sender_domain: str,
        subject: str,
        headers: dict[str, list[str]],
        message: Message,
    ) -> CheckResult:
        # Run the actual similarity evaluation, then decide whether the
        # sender domain should be remembered in history.
        result = self._evaluate(sender, sender_domain, subject, headers, message)

        # Record the sender domain in history ONLY when the similarity
        # trigger did NOT fire. A domain flagged as a lookalike must never
        # become a reference for future comparisons — otherwise a detected
        # typosquat would pollute the reference set and could mask or
        # cascade into future detections (e.g. once "gmai.com" is recorded,
        # the legitimate "gmail.com" would start matching it and get
        # falsely flagged).
        if not result.triggered:
            self._record_domain(sender_domain)

        return result

    def _evaluate(
        self,
        sender: str,
        sender_domain: str,
        subject: str,
        headers: dict[str, list[str]],
        message: Message,
    ) -> CheckResult:
        # Skip very short domains — too many false positives
        if len(sender_domain) < self.min_length:
            return CheckResult(
                triggered=False,
                reason=f"Domain '{sender_domain}' is too short for fuzzy analysis",
            )

        # Skip trusted sender domains (exact match OR subdomain of a trusted
        # domain — see _is_trusted). Legitimate domains and their subdomains
        # must never be flagged as lookalikes of sibling/typosquat domains.
        if self._is_trusted(sender_domain):
            return CheckResult(
                triggered=False,
                reason=f"Sender domain '{sender_domain}' is in trusted list",
                details={"domain": sender_domain, "trusted": True},
            )

        # Build the reference set: known domains + history (excluding self)
        references = set(self.known_domains) | self._history
        references.discard(sender_domain.lower())

        if not references:
            return CheckResult(
                triggered=False,
                reason="No reference domains available for comparison",
            )
        if sender_domain in references:
            return CheckResult(
                triggered=False,
                reason="Sender domain is in known list",
            )

        # Find the best match
        best_domain = ""
        best_score = 0.0
        sender_tld = sender_domain.rsplit(".", 1)[-1].lower() if "." in sender_domain else ""

        for ref in references:
            # Optionally skip references with the same TLD — same-TLD similarity
            # is common and usually benign (e.g. mail.ru ↔ yandex.ru)
            if self.same_tld_skip:
                ref_tld = ref.rsplit(".", 1)[-1].lower() if "." in ref else ""
                if ref_tld == sender_tld:
                    continue
            score = _domain_similarity(sender_domain, ref)
            if score > best_score:
                best_score = score
                best_domain = ref

        if best_score >= self.similarity_threshold:
            return CheckResult(
                triggered=True,
                reason=(
                    f"Domain '{sender_domain}' is similar to '{best_domain}' "
                    f"(similarity: {best_score:.3f})"
                ),
                details={
                    "sender_domain": sender_domain,
                    "matched_domain": best_domain,
                    "similarity": round(best_score, 4),
                    "threshold": self.similarity_threshold,
                },
            )

        return CheckResult(
            triggered=False,
            reason=(
                f"Domain '{sender_domain}' best match '{best_domain}' "
                f"similarity {best_score:.3f} below threshold {self.similarity_threshold}"
            ),
            details={
                "sender_domain": sender_domain,
                "best_match": best_domain,
                "similarity": round(best_score, 4),
            },
        )

    # ---- history management ----------------------------------------------

    def _record_domain(self, domain: str) -> None:
        """Add a domain to the in-memory history and persist."""
        self._history.add(domain.lower())
        if len(self._history) > self.history_max_entries:
            # Simple eviction: trim to 80 % of max
            self._history = set(list(self._history)[: int(self.history_max_entries * 0.8)])
        if self.history_file:
            self._save_history()

    def _load_history(self) -> None:
        """Load domain history from JSON file."""
        path = Path(self.history_file)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._history = set(str(d).lower() for d in data)
                    logger.info("Loaded %d domains from history file", len(self._history))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load history from %s: %s", path, exc)

    def _save_history(self) -> None:
        """Persist domain history to JSON file."""
        if not self.history_file:
            return
        path = Path(self.history_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic-ish write
            tmp = path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(sorted(self._history), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(str(tmp), str(path))
        except OSError as exc:
            logger.warning("Failed to save history to %s: %s", path, exc)
