"""Desktop coordination for authorized live capture and local PCAP replay."""

from dataclasses import asdict
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from stoa_desktop.session import DesktopSession
from stoa_security.ids import Indicator, MetadataIds
from stoa_security.packet_analysis import PacketMetadata, filter_metadata, replay_pcap, summarize
from stoa_security.packet_capture import CaptureConfig, LocalPacketCapture, capture_interfaces


class PacketAnalysisService:
    def __init__(self, session: DesktopSession) -> None:
        self.session = session
        self.rows: list[PacketMetadata] = []
        self.indicators: list[Indicator] = []
        self.capture: LocalPacketCapture | None = None
        self.job_id: str | None = None

    def options(self) -> dict[str, Any]:
        return {
            "interfaces": capture_interfaces(),
            "scopes": self.session.client.get("/api/v1/authorization-scopes"),
        }

    def start_live(
        self,
        *,
        interface: str,
        scope_id: UUID,
        target_network: str,
        justification: str,
        handler: Any,
    ) -> None:
        endpoint_id = self.session.settings.endpoint_id
        if endpoint_id is None:
            raise RuntimeError("enroll this endpoint before capturing")
        configuration = {
            "interface": interface,
            "protocols": ["tcp", "udp", "icmp", "arp", "dns", "http", "tls", "other"],
            "packet_limit": 100_000,
            "maximum_file_bytes": 50_000_000,
            "retained_files": 5,
            "replay_only": False,
        }
        job = cast(
            dict[str, Any],
            self.session.client.post(
                "/api/v1/jobs",
                {
                    "module_id": "packet-analysis",
                    "executing_endpoint_id": str(endpoint_id),
                    "authorization_scope_id": str(scope_id),
                    "target": target_network,
                    "business_justification": justification,
                    "configuration": configuration,
                },
            ),
        )
        effective = job["configuration"]
        self.rows = []
        self.indicators = []

        def received(metadata: PacketMetadata, indicators: tuple[Indicator, ...]) -> None:
            self.rows.append(metadata)
            self.indicators.extend(indicators)
            handler(metadata, indicators)

        self.capture = LocalPacketCapture(
            CaptureConfig(
                interface=interface,
                allowed_networks=(target_network,),
                protocols=frozenset(effective["protocols"]),
                packet_limit=effective["packet_limit"],
                maximum_file_bytes=effective["maximum_file_bytes"],
                retained_files=effective["retained_files"],
            ),
            received,
        )
        self.job_id = str(job["id"])
        self.capture.start()

    def stop_live(self) -> dict[str, Any]:
        if self.capture is None or self.job_id is None:
            raise RuntimeError("no capture is running")
        self.capture.stop()
        summary = summarize(self.rows)
        endpoint_id = self.session.settings.endpoint_id
        payload = {
            "executing_endpoint_id": str(endpoint_id),
            "packet_count": summary.packet_count,
            "byte_count": summary.byte_count,
            "protocols": summary.protocols,
            "indicators": [self._indicator_payload(item) for item in self.indicators],
            "cancelled": False,
        }
        result = self.session.client.post(
            f"/api/v1/jobs/{self.job_id}/packet-analysis-results", payload
        )
        return cast(dict[str, Any], result)

    def replay(self, path: Path) -> tuple[list[PacketMetadata], list[Indicator]]:
        detector = MetadataIds()
        self.rows = list(replay_pcap(path))
        self.indicators = [indicator for row in self.rows for indicator in detector.inspect(row)]
        return self.rows, self.indicators

    def filtered(self, protocol: str | None, search: str) -> list[PacketMetadata]:
        return filter_metadata(self.rows, protocol=protocol, search=search)

    @staticmethod
    def _indicator_payload(indicator: Indicator) -> dict[str, Any]:
        payload = asdict(indicator)
        payload["severity"] = indicator.severity.value
        payload["observed_at"] = indicator.observed_at.isoformat()
        payload.pop("observed_at")
        return payload
