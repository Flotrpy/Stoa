"""Desktop orchestration for endpoint integrity monitoring."""

import hashlib
import json
import platform
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from stoa_desktop.session import DesktopSession
from stoa_security.endpoint_monitoring import build_baseline, compare_baselines


class EndpointMonitoringService:
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
        root: Path,
        scope_id: UUID,
        justification: str,
        baseline_path: Path,
        recursive: bool = True,
    ) -> dict[str, Any]:
        endpoint_id = self.session.settings.endpoint_id
        if endpoint_id is None or self.session.principal is None:
            raise RuntimeError("connect and enroll this endpoint before monitoring files")
        current = build_baseline(root, recursive=recursive, exclude=(".stoa-baseline.json",))
        previous = {}
        if baseline_path.exists():
            from stoa_security.endpoint_monitoring import FileRecord

            previous = {
                key: FileRecord(**value)
                for key, value in json.loads(baseline_path.read_text(encoding="utf-8")).items()
            }
        baseline_id = hashlib.sha256(
            json.dumps(
                {key: value.sha256 for key, value in sorted(current.items())},
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        events = compare_baselines(previous, current, seed=baseline_id) if previous else ()
        job = cast(
            dict[str, Any],
            self.session.client.post(
                "/api/v1/jobs",
                {
                    "module_id": "endpoint-monitoring",
                    "executing_endpoint_id": str(endpoint_id),
                    "authorization_scope_id": str(scope_id),
                    "target": "127.0.0.1",
                    "business_justification": justification,
                    "configuration": {
                        "root": str(root.resolve()),
                        "recursive": recursive,
                        "include": ["*"],
                        "exclude": [],
                        "inspect_processes": False,
                    },
                },
            ),
        )
        observations = [
            {
                "observation_type": "integrity",
                "rule_id": f"STOA-FIM-{event.kind.upper()}",
                "title": f"File {event.kind}",
                "severity": "medium" if event.kind in {"changed", "deleted"} else "low",
                "confidence": 1.0,
                "subject": event.path,
                "explanation": f"Baseline comparison observed a {event.kind} event.",
                "evidence": {"previous_path": event.previous_path or ""},
                "chain_hash": event.chain_hash,
            }
            for event in events
        ]
        result = self.session.client.post(
            f"/api/v1/jobs/{job['id']}/endpoint-monitoring-results",
            {
                "executing_endpoint_id": str(endpoint_id),
                "baseline_id": baseline_id,
                "observations": observations,
            },
        )
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps({key: asdict(value) for key, value in current.items()}, indent=2),
            encoding="utf-8",
        )
        return cast(dict[str, Any], result)

    @staticmethod
    def platform_name() -> str:
        return "windows" if platform.system().casefold() == "windows" else "linux"
