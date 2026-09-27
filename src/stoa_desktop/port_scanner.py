"""Desktop orchestration for centrally authorized local port scans."""

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from stoa_desktop.session import DesktopSession
from stoa_security.contracts import AuthorizationContext
from stoa_security.port_scanner import (
    AuthorizedPortScanner,
    PortScanConfig,
    ScanMethod,
    parse_ports,
)

ProgressHandler = Callable[[int, int], None]


class PortScanService:
    def __init__(self, session: DesktopSession) -> None:
        self.session = session
        self._cancel: asyncio.Event | None = None

    def cancel(self) -> None:
        if self._cancel is not None:
            self._cancel.set()

    def options(self) -> dict[str, Any]:
        return {
            "endpoints": self.session.client.get("/api/v1/endpoints"),
            "scopes": self.session.client.get("/api/v1/authorization-scopes"),
        }

    def run(
        self,
        *,
        target: str,
        port_specification: str,
        scope_id: UUID,
        justification: str,
        progress: ProgressHandler | None = None,
    ) -> dict[str, Any]:
        endpoint_id = self.session.settings.endpoint_id
        principal = self.session.principal
        if endpoint_id is None or principal is None:
            raise RuntimeError("connect and enroll this endpoint before scanning")
        scopes = cast(list[dict[str, Any]], self.session.client.get("/api/v1/authorization-scopes"))
        scope = next((item for item in scopes if item["id"] == str(scope_id)), None)
        if scope is None:
            raise RuntimeError("authorization scope is no longer available")
        ports = parse_ports(port_specification)
        rate_policy = cast(dict[str, int], scope["rate_policy"])
        attempts_per_second = min(500, rate_policy["max_requests"])
        minimum_interval = rate_policy["window_seconds"] / rate_policy["max_requests"]
        timeout_seconds = 1.0
        concurrency = min(64, len(ports))
        collect_banners = True
        configuration = {
            "ports": list(ports),
            "method": "tcp-connect",
            "timeout_seconds": timeout_seconds,
            "concurrency": concurrency,
            "max_attempts_per_second": attempts_per_second,
            "collect_banners": collect_banners,
        }
        job = cast(
            dict[str, Any],
            self.session.client.post(
                "/api/v1/jobs",
                {
                    "module_id": "port-scanner",
                    "executing_endpoint_id": str(endpoint_id),
                    "authorization_scope_id": str(scope_id),
                    "target": target,
                    "business_justification": justification,
                    "configuration": configuration,
                },
            ),
        )
        authorization = AuthorizationContext(
            scope_id=scope_id,
            requesting_user_id=UUID(str(principal["user"]["id"])),
            executing_endpoint_id=endpoint_id,
            target=target,
            valid_from=datetime.fromisoformat(scope["valid_from"]),
            expires_at=datetime.fromisoformat(scope["expires_at"]),
            business_justification=justification,
            correlation_id=UUID(str(job["correlation_id"])),
        )

        async def execute() -> dict[str, Any]:
            self._cancel = asyncio.Event()

            async def on_progress(scanned: int, total: int, observation: object) -> None:
                del observation
                if progress is not None:
                    progress(scanned, total)

            report = await AuthorizedPortScanner(authorization).scan(
                PortScanConfig(
                    target=target,
                    ports=ports,
                    method=ScanMethod.TCP_CONNECT,
                    timeout_seconds=timeout_seconds,
                    concurrency=concurrency,
                    max_attempts_per_second=attempts_per_second,
                    minimum_interval_seconds=minimum_interval,
                    collect_banners=collect_banners,
                ),
                cancel=self._cancel,
                progress=on_progress,
            )
            result = self.session.client.post(
                f"/api/v1/jobs/{job['id']}/port-scan-results",
                {
                    "executing_endpoint_id": str(endpoint_id),
                    "cancelled": report.cancelled,
                    "observations": [
                        {
                            "port": item.port,
                            "state": item.state.value,
                            "service": item.service,
                            "banner": item.banner,
                            "latency_ms": item.latency_ms,
                        }
                        for item in report.observations
                    ],
                },
            )
            self._cancel = None
            return cast(dict[str, Any], result)

        return asyncio.run(execute())
