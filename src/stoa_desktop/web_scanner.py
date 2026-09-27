"""Desktop orchestration for authorized same-origin web scans."""

from typing import Any, cast
from uuid import UUID

from stoa_desktop.session import DesktopSession
from stoa_security.web_scanner import AuthorizedWebScanner, WebScanConfig


class WebScanService:
    def __init__(self, session: DesktopSession) -> None:
        self.session = session

    def options(self) -> dict[str, Any]:
        return {
            "endpoints": self.session.client.get("/api/v1/endpoints"),
            "scopes": self.session.client.get("/api/v1/authorization-scopes"),
        }

    def run(
        self,
        *,
        target_url: str,
        scope_id: UUID,
        justification: str,
        max_depth: int,
        max_pages: int,
        active_checks: bool,
        allow_form_submission: bool,
    ) -> dict[str, Any]:
        endpoint_id = self.session.settings.endpoint_id
        if endpoint_id is None or self.session.principal is None:
            raise RuntimeError("connect and enroll this endpoint before web scanning")
        configuration = {
            "max_depth": max_depth,
            "max_pages": max_pages,
            "max_requests_per_second": 5,
            "timeout_seconds": 5.0,
            "active_checks": active_checks,
            "allow_form_submission": allow_form_submission,
            "import_zap_alerts": False,
        }
        job = cast(
            dict[str, Any],
            self.session.client.post(
                "/api/v1/jobs",
                {
                    "module_id": "web-scanner",
                    "executing_endpoint_id": str(endpoint_id),
                    "authorization_scope_id": str(scope_id),
                    "target": target_url,
                    "business_justification": justification,
                    "configuration": configuration,
                },
            ),
        )
        effective = cast(dict[str, Any], job["configuration"])
        report = AuthorizedWebScanner(
            WebScanConfig(
                start_url=target_url,
                max_depth=int(effective["max_depth"]),
                max_pages=int(effective["max_pages"]),
                max_requests_per_second=int(effective["max_requests_per_second"]),
                timeout_seconds=float(effective["timeout_seconds"]),
                active_checks=bool(effective["active_checks"]),
                allow_form_submission=bool(effective["allow_form_submission"]),
            )
        ).scan()
        result = self.session.client.post(
            f"/api/v1/jobs/{job['id']}/web-scan-results",
            {
                "executing_endpoint_id": str(endpoint_id),
                "page_count": report.page_count,
                "cancelled": report.cancelled,
                "findings": [
                    {
                        "rule_id": item.rule_id,
                        "title": item.title,
                        "category": item.category,
                        "severity": item.severity,
                        "confidence": item.confidence,
                        "url": item.url,
                        "evidence": item.evidence,
                        "remediation": item.remediation,
                    }
                    for item in report.findings
                ],
            },
        )
        return cast(dict[str, Any], result)
