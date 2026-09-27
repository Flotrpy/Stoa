"""Deterministic explainable IDS indicators over packet metadata."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from stoa_security.packet_analysis import PacketMetadata, dns_entropy


class IndicatorSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Indicator:
    rule_id: str
    title: str
    severity: IndicatorSeverity
    confidence: float
    explanation: str
    observed_at: datetime
    source: str | None
    destination: str | None
    evidence: dict[str, str | int | float]


class MetadataIds:
    """Stateful rules that never require centrally retained packet payloads."""

    def __init__(
        self,
        *,
        port_scan_threshold: int = 20,
        port_scan_window_seconds: int = 10,
        dns_entropy_threshold: float = 3.7,
    ) -> None:
        if not 5 <= port_scan_threshold <= 10_000:
            raise ValueError("port scan threshold must be between 5 and 10000")
        if not 1 <= port_scan_window_seconds <= 3600:
            raise ValueError("port scan window must be between 1 and 3600 seconds")
        if not 1 <= dns_entropy_threshold <= 8:
            raise ValueError("DNS entropy threshold must be between 1 and 8")
        self.port_scan_threshold = port_scan_threshold
        self.window = timedelta(seconds=port_scan_window_seconds)
        self.dns_entropy_threshold = dns_entropy_threshold
        self._connections: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self._arp_bindings: dict[str, str] = {}
        self._emitted_scans: set[tuple[str, str]] = set()

    def inspect(self, packet: PacketMetadata) -> list[Indicator]:
        indicators: list[Indicator] = []
        scan = self._port_scan_indicator(packet)
        if scan is not None:
            indicators.append(scan)
        arp = self._arp_change_indicator(packet)
        if arp is not None:
            indicators.append(arp)
        dns = self._dns_entropy_indicator(packet)
        if dns is not None:
            indicators.append(dns)
        cleartext = self._cleartext_service_indicator(packet)
        if cleartext is not None:
            indicators.append(cleartext)
        return indicators

    def _port_scan_indicator(self, packet: PacketMetadata) -> Indicator | None:
        if (
            packet.protocol != "tcp"
            or packet.source is None
            or packet.destination is None
            or packet.destination_port is None
            or packet.tcp_flags not in {"S", "SCE"}
        ):
            return None
        key = (packet.source, packet.destination)
        attempts = self._connections[key]
        attempts.append((packet.observed_at, packet.destination_port))
        cutoff = packet.observed_at - self.window
        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()
        unique_ports = len({port for _, port in attempts})
        if unique_ports < self.port_scan_threshold or key in self._emitted_scans:
            return None
        self._emitted_scans.add(key)
        return Indicator(
            rule_id="STOA-NET-001",
            title="Rapid connection attempts across multiple ports",
            severity=IndicatorSeverity.MEDIUM,
            confidence=0.85,
            explanation=(
                "One source attempted many destination ports within the configured window. "
                "Administrative discovery and monitoring can produce the same pattern."
            ),
            observed_at=packet.observed_at,
            source=packet.source,
            destination=packet.destination,
            evidence={
                "unique_ports": unique_ports,
                "window_seconds": int(self.window.total_seconds()),
            },
        )

    def _arp_change_indicator(self, packet: PacketMetadata) -> Indicator | None:
        if packet.protocol != "arp" or packet.source is None or packet.source_mac is None:
            return None
        previous = self._arp_bindings.get(packet.source)
        self._arp_bindings[packet.source] = packet.source_mac
        if previous is None or previous.casefold() == packet.source_mac.casefold():
            return None
        return Indicator(
            rule_id="STOA-NET-002",
            title="ARP address binding changed",
            severity=IndicatorSeverity.MEDIUM,
            confidence=0.75,
            explanation=(
                "An IPv4 address appeared with a different MAC address. DHCP changes, failover, "
                "virtualization, and legitimate device replacement can cause this."
            ),
            observed_at=packet.observed_at,
            source=packet.source,
            destination=packet.destination,
            evidence={"previous_mac": previous, "current_mac": packet.source_mac},
        )

    def _dns_entropy_indicator(self, packet: PacketMetadata) -> Indicator | None:
        if not packet.dns_query:
            return None
        entropy = dns_entropy(packet.dns_query)
        first_label = packet.dns_query.split(".", maxsplit=1)[0]
        if len(first_label) < 20 or entropy < self.dns_entropy_threshold:
            return None
        return Indicator(
            rule_id="STOA-NET-003",
            title="High-entropy DNS label",
            severity=IndicatorSeverity.LOW,
            confidence=0.55,
            explanation=(
                "A long DNS label has high character entropy. CDNs, tracking identifiers, and "
                "security products commonly produce similar names."
            ),
            observed_at=packet.observed_at,
            source=packet.source,
            destination=packet.destination,
            evidence={"query": packet.dns_query[:253], "entropy": round(entropy, 3)},
        )

    @staticmethod
    def _cleartext_service_indicator(packet: PacketMetadata) -> Indicator | None:
        if packet.destination_port not in {21, 23, 110, 143}:
            return None
        return Indicator(
            rule_id="STOA-NET-004",
            title="Connection to conventionally cleartext service",
            severity=IndicatorSeverity.INFO,
            confidence=0.7,
            explanation=(
                "Traffic used a port commonly associated with a cleartext protocol. Port numbers "
                "alone do not prove that sensitive content was transmitted."
            ),
            observed_at=packet.observed_at,
            source=packet.source,
            destination=packet.destination,
            evidence={"destination_port": packet.destination_port},
        )
