"""Explainable phishing risk scoring with a versioned scikit-learn pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse

from sklearn.feature_extraction import DictVectorizer  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]

MODEL_VERSION = "stoa-phishing-2026.09.1"
TRAINING_PROVENANCE = "Synthetic, hand-reviewed defensive URL/page fixtures; no user data"
KNOWN_LIMITATIONS = (
    "Small synthetic training set; no domain-age lookup; brand context and redirects must be "
    "supplied; "
    "score is triage guidance, not a verdict."
)


@dataclass(frozen=True, slots=True)
class PageFacts:
    url: str
    redirect_count: int = 0
    tls_valid: bool | None = None
    domain_age_days: int | None = None
    form_actions: tuple[str, ...] = ()
    password_fields: int = 0
    external_resource_ratio: float = 0.0
    title: str = ""
    expected_brand: str | None = None
    suspicious_text_hits: int = 0
    obfuscated_links: int = 0


@dataclass(frozen=True, slots=True)
class PhishingAssessment:
    score: float
    level: str
    explanations: tuple[str, ...]
    model_version: str


def extract_features(facts: PageFacts) -> tuple[dict[str, float], tuple[str, ...]]:
    parsed = urlparse(facts.url)
    host = (parsed.hostname or "").casefold()
    explanations: list[str] = []
    ip_host = _is_ip(host)
    punycode = "xn--" in host
    many_subdomains = host.count(".") >= 3
    long_url = len(facts.url) >= 100
    password_cross_origin = (
        any(urlparse(action).hostname not in {None, host} for action in facts.form_actions)
        and facts.password_fields > 0
    )
    title_mismatch = bool(
        facts.expected_brand and facts.expected_brand.casefold() not in facts.title.casefold()
    )
    signals = (
        (ip_host, "URL uses an IP address instead of a domain"),
        (punycode, "Domain contains Punycode and may be a lookalike"),
        (many_subdomains, "Domain has an unusually deep subdomain chain"),
        (long_url, "URL is unusually long"),
        (facts.redirect_count >= 3, "Redirect chain is unusually long"),
        (facts.tls_valid is False, "TLS validation failed"),
        (password_cross_origin, "Password form posts to another origin"),
        (title_mismatch, "Page title does not match the expected brand"),
        (facts.external_resource_ratio >= 0.7, "Most page resources are cross-origin"),
        (facts.obfuscated_links > 0, "Page contains obfuscated links"),
        (facts.suspicious_text_hits > 0, "Page contains urgency or credential-harvesting language"),
    )
    explanations.extend(message for active, message in signals if active)
    features = {
        "ip_host": float(ip_host),
        "punycode": float(punycode),
        "many_subdomains": float(many_subdomains),
        "long_url": float(long_url),
        "redirects": min(facts.redirect_count, 10) / 10,
        "tls_invalid": float(facts.tls_valid is False),
        "young_domain": float(facts.domain_age_days is not None and facts.domain_age_days < 30),
        "password_cross_origin": float(password_cross_origin),
        "password_fields": min(facts.password_fields, 5) / 5,
        "external_ratio": max(0.0, min(facts.external_resource_ratio, 1.0)),
        "title_mismatch": float(title_mismatch),
        "suspicious_text": min(facts.suspicious_text_hits, 10) / 10,
        "obfuscated_links": min(facts.obfuscated_links, 10) / 10,
    }
    return features, tuple(explanations)


def build_pipeline() -> Pipeline:
    pipeline = Pipeline(
        [
            ("vectorizer", DictVectorizer(sparse=False)),
            ("classifier", LogisticRegression(random_state=17, max_iter=500)),
        ]
    )
    safe = [
        PageFacts("https://docs.example.com/help", tls_valid=True, domain_age_days=3000),
        PageFacts("https://portal.example.org/login", tls_valid=True, password_fields=1),
        PageFacts("https://shop.example.net/cart", tls_valid=True, external_resource_ratio=0.2),
        PageFacts("https://status.example.com", tls_valid=True, redirect_count=1),
    ]
    risky = [
        PageFacts(
            "http://192.0.2.4/login", tls_valid=False, password_fields=1, suspicious_text_hits=4
        ),
        PageFacts("https://xn--paypa-4ve.example/verify", password_fields=2, obfuscated_links=3),
        PageFacts("https://a.b.c.d.example/secure", redirect_count=5, external_resource_ratio=0.9),
        PageFacts(
            "https://accounts.example/login",
            form_actions=("https://collector.invalid/submit",),
            password_fields=1,
            suspicious_text_hits=3,
        ),
    ]
    rows = [extract_features(item)[0] for item in (*safe, *risky)]
    pipeline.fit(rows, [0] * len(safe) + [1] * len(risky))
    return pipeline


def assess(facts: PageFacts, pipeline: Pipeline | None = None) -> PhishingAssessment:
    model = pipeline or build_pipeline()
    features, explanations = extract_features(facts)
    probability = float(model.predict_proba([features])[0][1])
    heuristic = min(1.0, len(explanations) / 6)
    score = round(0.65 * probability + 0.35 * heuristic, 4)
    level = "high" if score >= 0.7 else "medium" if score >= 0.4 else "low"
    return PhishingAssessment(score, level, explanations, MODEL_VERSION)


def _is_ip(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True
