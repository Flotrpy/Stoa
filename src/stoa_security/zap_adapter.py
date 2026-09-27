"""Optional OWASP ZAP metadata import for authorized web scans."""

from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from stoa_security.web_scanner import WebFinding, redacted_url


@dataclass(frozen=True, slots=True)
class ZapImportConfig:
    api_url: str = "http://127.0.0.1:8080"
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        parsed = urlparse(self.api_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
        }:
            raise ValueError("ZAP API imports must use an explicit local API URL")
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0.1 and 30")


def import_zap_alerts(config: ZapImportConfig, target_url: str) -> tuple[WebFinding, ...]:
    """Import existing ZAP alert metadata without starting spider or active scans."""

    with httpx.Client(base_url=config.api_url, timeout=config.timeout_seconds) as client:
        response = client.get("/JSON/core/view/alerts/", params={"baseurl": target_url})
        response.raise_for_status()
    alerts = response.json().get("alerts", [])
    findings: list[WebFinding] = []
    for alert in alerts[:500]:
        risk = str(alert.get("risk", "info")).casefold()
        severity = {"informational": "info", "low": "low", "medium": "medium", "high": "high"}.get(
            risk, "info"
        )
        confidence = {"false positive": 0.1, "low": 0.4, "medium": 0.65, "high": 0.85}.get(
            str(alert.get("confidence", "")).casefold(), 0.5
        )
        findings.append(
            WebFinding(
                rule_id="STOA-WEB-ZAP",
                title=str(alert.get("alert", "ZAP alert"))[:240],
                severity=severity,
                confidence=confidence,
                url=redacted_url(str(alert.get("url") or target_url)),
                evidence={"source": "zap", "plugin_id": str(alert.get("pluginId", ""))[:80]},
                remediation=str(alert.get("solution") or "Review the imported ZAP alert.")[:1000],
                category="zap",
            )
        )
    return tuple(findings)
