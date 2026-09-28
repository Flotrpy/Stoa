"""Local orchestration for phishing and password-risk analysis."""

from collections.abc import Iterable
from dataclasses import asdict
from typing import Any

from stoa_security.password_audit import audit_hash, rule_candidates
from stoa_security.phishing import PageFacts, assess


class RiskAnalysisService:
    def assess_page(self, facts: PageFacts) -> dict[str, Any]:
        return asdict(assess(facts))

    def audit_password_hash(
        self,
        digest: str,
        words: Iterable[str],
        *,
        max_attempts: int,
        max_seconds: float,
    ) -> dict[str, Any]:
        """Run locally; callers must never send digest or candidates to the API."""
        return asdict(
            audit_hash(
                digest,
                rule_candidates(words),
                max_attempts=max_attempts,
                max_seconds=max_seconds,
            )
        )
