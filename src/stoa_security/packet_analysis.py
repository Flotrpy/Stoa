"""Local-only packet metadata extraction, replay, filtering, and summaries."""

import math
import shutil
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapReader, PcapWriter


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    observed_at: datetime
    captured_length: int
    protocol: str
    source: str | None
    destination: str | None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    dns_query: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    tls_version: str | None = None
    arp_operation: str | None = None
    source_mac: str | None = None
    destination_mac: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["observed_at"] = self.observed_at.isoformat()
        return payload


def packet_metadata(packet: Packet) -> PacketMetadata:
    """Extract bounded protocol metadata without retaining packet payload bytes."""

    observed_at = datetime.fromtimestamp(float(packet.time), tz=UTC)
    source: str | None = None
    destination: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    protocol = "other"
    dns_query: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    tls_version: str | None = None
    arp_operation: str | None = None

    if packet.haslayer(ARP):
        arp = packet[ARP]
        protocol = "arp"
        source = str(arp.psrc)
        destination = str(arp.pdst)
        arp_operation = {1: "request", 2: "reply"}.get(int(arp.op), "other")
    elif packet.haslayer(IP):
        internet = packet[IP]
        source = str(internet.src)
        destination = str(internet.dst)
        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "tcp"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            tcp_flags = str(transport.flags)
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "udp"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
        elif packet.haslayer(ICMP):
            protocol = "icmp"

    if packet.haslayer(DNS):
        protocol = "dns"
        dns = packet[DNS]
        questions = dns.qd
        question = questions[0] if questions else None
        if question is not None and hasattr(question, "qname"):
            raw_query = bytes(question.qname)[:253]
            dns_query = raw_query.decode("ascii", "replace").rstrip(".")

    payload = bytes(packet[Raw].load)[:1024] if packet.haslayer(Raw) else b""
    if payload and source_port is not None and destination_port is not None:
        http_method, http_host, http_path = _http_metadata(payload)
        if http_method:
            protocol = "http"
        tls_version = _tls_version(payload)
        if tls_version:
            protocol = "tls"

    ether = packet[Ether] if packet.haslayer(Ether) else None
    return PacketMetadata(
        observed_at=observed_at,
        captured_length=len(packet),
        protocol=protocol,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        http_method=http_method,
        http_host=http_host,
        http_path=http_path,
        tls_version=tls_version,
        arp_operation=arp_operation,
        source_mac=str(ether.src) if ether is not None else None,
        destination_mac=str(ether.dst) if ether is not None else None,
    )


def _http_metadata(payload: bytes) -> tuple[str | None, str | None, str | None]:
    try:
        header = payload.split(b"\r\n\r\n", maxsplit=1)[0].decode("iso-8859-1")
    except UnicodeDecodeError:
        return None, None, None
    lines = header.split("\r\n")
    if not lines:
        return None, None, None
    parts = lines[0].split(" ")
    methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    if len(parts) != 3 or parts[0] not in methods or not parts[2].startswith("HTTP/"):
        return None, None, None
    host = next(
        (
            line.split(":", maxsplit=1)[1].strip()
            for line in lines[1:]
            if line.lower().startswith("host:")
        ),
        None,
    )
    return parts[0], host[:253] if host else None, parts[1][:512]


def _tls_version(payload: bytes) -> str | None:
    if len(payload) < 3 or payload[0] not in {20, 21, 22, 23} or payload[1] != 3:
        return None
    return {0: "SSLv3", 1: "TLS1.0", 2: "TLS1.1", 3: "TLS1.2", 4: "TLS1.3"}.get(
        payload[2], f"TLS-3.{payload[2]}"
    )


@dataclass(frozen=True, slots=True)
class TrafficSummary:
    packet_count: int
    byte_count: int
    protocols: dict[str, int]
    top_sources: dict[str, int]
    top_destinations: dict[str, int]


def summarize(packets: Iterable[PacketMetadata]) -> TrafficSummary:
    rows = list(packets)
    return TrafficSummary(
        packet_count=len(rows),
        byte_count=sum(item.captured_length for item in rows),
        protocols=dict(Counter(item.protocol for item in rows)),
        top_sources=dict(Counter(item.source for item in rows if item.source).most_common(10)),
        top_destinations=dict(
            Counter(item.destination for item in rows if item.destination).most_common(10)
        ),
    )


def filter_metadata(
    packets: Iterable[PacketMetadata], *, protocol: str | None = None, search: str = ""
) -> list[PacketMetadata]:
    needle = search.casefold().strip()
    return [
        item
        for item in packets
        if (protocol is None or item.protocol == protocol)
        and (
            not needle
            or needle
            in " ".join(
                str(value) for value in asdict(item).values() if value is not None
            ).casefold()
        )
    ]


def replay_pcap(path: Path, *, limit: int = 100_000) -> Iterator[PacketMetadata]:
    if limit < 1 or limit > 1_000_000:
        raise ValueError("replay limit must be between 1 and 1000000")
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader):
            if index >= limit:
                break
            yield packet_metadata(packet)


class RotatingPcapStore:
    """Bounded local PCAP storage; export is always an explicit user action."""

    def __init__(
        self, directory: Path, *, maximum_file_bytes: int = 50_000_000, retained_files: int = 5
    ) -> None:
        if not 1_000 <= maximum_file_bytes <= 2_000_000_000:
            raise ValueError("PCAP size limit must be between 1000 and 2000000000 bytes")
        if not 1 <= retained_files <= 100:
            raise ValueError("retained PCAP count must be between 1 and 100")
        self.directory = directory
        self.maximum_file_bytes = maximum_file_bytes
        self.retained_files = retained_files
        self.directory.mkdir(parents=True, exist_ok=True)
        self._writer: PcapWriter | None = None
        self._path: Path | None = None

    def write(self, packet: Packet) -> Path:
        if self._path is None or (
            self._path.exists() and self._path.stat().st_size >= self.maximum_file_bytes
        ):
            self._rotate()
        if self._writer is None or self._path is None:
            raise RuntimeError("PCAP writer did not initialize")
        self._writer.write(packet)
        self._writer.flush()
        return self._path

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
        self._writer = None

    def export(self, source: Path, destination: Path) -> Path:
        resolved_source = source.resolve()
        if self.directory.resolve() not in resolved_source.parents:
            raise ValueError("only managed PCAP files can be exported")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination

    def _rotate(self) -> None:
        self.close()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        self._path = self.directory / f"capture-{stamp}.pcap"
        self._writer = PcapWriter(str(self._path), append=False, sync=True)
        captures = sorted(
            self.directory.glob("capture-*.pcap"), key=lambda item: item.stat().st_mtime
        )
        for expired in captures[: max(0, len(captures) - self.retained_files + 1)]:
            expired.unlink()


def dns_entropy(query: str) -> float:
    label = query.split(".", maxsplit=1)[0].casefold()
    if not label:
        return 0.0
    counts = Counter(label)
    return -sum((count / len(label)) * math.log2(count / len(label)) for count in counts.values())
