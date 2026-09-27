"""Explicit local packet capture with bounded retention and clean cancellation."""

from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from threading import Lock

from platformdirs import user_data_path
from scapy.all import AsyncSniffer, get_if_list
from scapy.packet import Packet

from stoa_security.ids import Indicator, MetadataIds
from stoa_security.packet_analysis import PacketMetadata, RotatingPcapStore, packet_metadata

PacketHandler = Callable[[PacketMetadata, tuple[Indicator, ...]], None]

_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "arp", "dns", "http", "tls", "other"})


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    interface: str
    allowed_networks: tuple[str, ...]
    protocols: frozenset[str] = _PROTOCOLS
    packet_limit: int = 100_000
    maximum_file_bytes: int = 50_000_000
    retained_files: int = 5

    def __post_init__(self) -> None:
        if not self.interface or len(self.interface) > 512:
            raise ValueError("a valid interface is required")
        if not self.allowed_networks:
            raise ValueError("at least one authorized network is required")
        for network in self.allowed_networks:
            ip_network(network, strict=False)
        if not self.protocols or not self.protocols <= _PROTOCOLS:
            raise ValueError("protocol filter contains unsupported values")
        if not 1 <= self.packet_limit <= 1_000_000:
            raise ValueError("packet limit must be between 1 and 1000000")


def capture_interfaces() -> tuple[str, ...]:
    return tuple(sorted(str(interface) for interface in get_if_list()))


class LocalPacketCapture:
    """Own a Scapy capture whose PCAP bytes never leave local storage implicitly."""

    def __init__(
        self,
        config: CaptureConfig,
        handler: PacketHandler,
        *,
        data_directory: Path | None = None,
        ids: MetadataIds | None = None,
    ) -> None:
        if config.interface not in capture_interfaces():
            raise ValueError("selected capture interface is unavailable")
        self.config = config
        self.handler = handler
        self.ids = ids or MetadataIds()
        directory = data_directory or user_data_path("Stoa", "Flotrpy") / "captures"
        self.store = RotatingPcapStore(
            directory,
            maximum_file_bytes=config.maximum_file_bytes,
            retained_files=config.retained_files,
        )
        self._sniffer: AsyncSniffer | None = None
        self._count = 0
        self._lock = Lock()

    @property
    def running(self) -> bool:
        return bool(self._sniffer is not None and self._sniffer.running)

    def start(self) -> None:
        if self.running:
            raise RuntimeError("capture is already running")
        self._sniffer = AsyncSniffer(
            iface=self.config.interface,
            prn=self._receive,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None and self._sniffer.running:
            self._sniffer.stop(join=True)
        self.store.close()

    def _receive(self, packet: Packet) -> None:
        metadata = packet_metadata(packet)
        if metadata.protocol not in self.config.protocols:
            return
        if not self._is_authorized(metadata):
            return
        with self._lock:
            if self._count >= self.config.packet_limit:
                return
            self._count += 1
            self.store.write(packet)
        indicators = tuple(self.ids.inspect(metadata))
        self.handler(metadata, indicators)
        if self._count >= self.config.packet_limit:
            if self._sniffer is not None:
                self._sniffer.stop(join=False)
            self.store.close()

    def _is_authorized(self, metadata: PacketMetadata) -> bool:
        networks = [ip_network(value, strict=False) for value in self.config.allowed_networks]
        for value in (metadata.source, metadata.destination):
            if value is None:
                continue
            try:
                if any(ip_address(value) in network for network in networks):
                    return True
            except ValueError:
                continue
        return False
