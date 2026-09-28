import hashlib

import pytest

from stoa_security.password_audit import (
    audit_hash,
    brute_force_candidates,
    detect_hash_format,
    rule_candidates,
)
from stoa_security.phishing import MODEL_VERSION, PageFacts, assess, extract_features


def test_phishing_assessment_keeps_heuristic_explanations() -> None:
    facts = PageFacts(
        "http://192.0.2.20/urgent-login",
        tls_valid=False,
        redirect_count=5,
        form_actions=("https://collector.invalid/submit",),
        password_fields=1,
        suspicious_text_hits=4,
        external_resource_ratio=0.9,
    )
    result = assess(facts)
    assert result.level == "high"
    assert result.model_version == MODEL_VERSION
    assert "Password form posts to another origin" in result.explanations


def test_safe_page_has_low_risk_and_feature_bounds() -> None:
    facts = PageFacts("https://docs.example.com/help", tls_valid=True, domain_age_days=1000)
    features, explanations = extract_features(facts)
    assert assess(facts).level == "low"
    assert not explanations
    assert all(0 <= value <= 1 for value in features.values())


def test_dictionary_rules_recover_demo_hash_locally() -> None:
    digest = hashlib.sha256(b"Example1").hexdigest()
    result = audit_hash(digest, rule_candidates(["example"]), max_attempts=10)
    assert detect_hash_format(digest) == "sha256-demo"
    assert result.matched
    assert result.candidate == "Example1"
    assert "Argon2id" in result.remediation


def test_brute_force_is_bounded_and_cancellable() -> None:
    digest = hashlib.md5(b"zz", usedforsecurity=False).hexdigest()
    limited = audit_hash(digest, brute_force_candidates("ab", 2), max_attempts=2)
    cancelled = audit_hash(digest, ["a", "b"], cancelled=lambda: True)
    assert not limited.matched and limited.attempts == 2
    assert cancelled.cancelled and cancelled.attempts == 0


def test_rejects_unsupported_hashes_and_unsafe_demo_size() -> None:
    with pytest.raises(ValueError, match="only hexadecimal"):
        detect_hash_format("not-a-supported-hash")
    with pytest.raises(ValueError, match="between 1 and 6"):
        tuple(brute_force_candidates("ab", 7))
