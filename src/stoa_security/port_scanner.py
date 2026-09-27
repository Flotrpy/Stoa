"""Bounded authorized IPv4 port and service scanning."""

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from stoa_security.contracts import AuthorizationContext

ProgressCallback = Callable[[int, int, "PortObservation"], Awaitable[None]]

PORT_PRESETS: dict[str, tuple[int, ...]] = {
    "web": (80, 443, 8000, 8080, 8443),
    "remote-admin": (22, 3389, 5985, 5986),
    "databases": (1433, 1521, 3306, 5432, 6379, 27017),
    "common": (21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3389),
}

_SERVICE_BY_PORT = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


class ScanMethod(StrEnum):
    TCP_CONNECT = "tcp-connect"
    SYN = "syn"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class PortScanConfig:
    target: str
    ports: tuple[int, ...]
    method: ScanMethod = ScanMethod.TCP_CONNECT
    timeout_seconds: float = 1.0
    concurrency: int = 64
    max_attempts_per_second: int = 100
    minimum_interval_seconds: float = 0.0
    collect_banners: bool = True

    def __post_init__(self) -> None:
        if not self.target or len(self.target) > 253:
            raise ValueError("target must be a hostname or IPv4 address")
        if not self.ports or len(self.ports) > 1024:
            raise ValueError("one to 1024 ports are required")
        if any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("ports must be between 1 and 65535")
        if tuple(sorted(set(self.ports))) != self.ports:
            raise ValueError("ports must be unique and sorted")
        if not 0.05 <= self.timeout_seconds <= 10:
            raise ValueError("timeout must be between 0.05 and 10 seconds")
        if not 1 <= self.concurrency <= 256:
            raise ValueError("concurrency must be between 1 and 256")
        if not 1 <= self.max_attempts_per_second <= 500:
            raise ValueError("rate must be between 1 and 500 attempts per second")
        if not 0 <= self.minimum_interval_seconds <= 86_400:
            raise ValueError("minimum interval must be between 0 and 86400 seconds")


@dataclass(frozen=True, slots=True)
class PortObservation:
    port: int
    state: PortState
    service: str | None
    banner: str | None
    latency_ms: float | None


@dataclass(frozen=True, slots=True)
class PortScanReport:
    target: str
    resolved_ipv4: str
    method: ScanMethod
    started_at: datetime
    completed_at: datetime
    cancelled: bool
    host_reachable: bool
    observations: tuple[PortObservation, ...]

    def as_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["method"] = self.method.value
        payload["started_at"] = self.started_at.isoformat()
        payload["completed_at"] = self.completed_at.isoformat()
        for observation in payload["observations"]:
            observation["state"] = observation["state"].value
        return payload

    def as_text(self) -> str:
        status = "cancelled" if self.cancelled else "completed"
        lines = [
            f"Port scan {status}: {self.target} ({self.resolved_ipv4})",
            f"Method: {self.method.value}",
            f"Host reachable: {'yes' if self.host_reachable else 'no'}",
            "",
            "PORT     STATE        SERVICE             BANNER",
        ]
        for item in self.observations:
            lines.append(
                f"{item.port:<8} {item.state.value:<12} "
                f"{(item.service or '-'):<19} {item.banner or '-'}"
            )
        return "\n".join(lines) + "\n"


def parse_ports(specification: str) -> tuple[int, ...]:
    """Parse comma-delimited ports, inclusive ranges, and approved preset names."""

    ports: set[int] = set()
    for raw_part in specification.split(","):
        part = raw_part.strip().casefold()
        if not part:
            raise ValueError("port specification contains an empty item")
        if part in PORT_PRESETS:
            ports.update(PORT_PRESETS[part])
            continue
        if re.fullmatch(r"\d+", part):
            ports.add(_valid_port(int(part)))
            continue
        match = re.fullmatch(r"(\d+)-(\d+)", part)
        if match is None:
            raise ValueError(f"invalid port item: {part}")
        start, end = (int(value) for value in match.groups())
        if start > end or end - start + 1 > 1024:
            raise ValueError("port ranges must be ascending and contain at most 1024 ports")
        ports.update(_valid_port(port) for port in range(start, end + 1))
        if len(ports) > 1024:
            raise ValueError("at most 1024 unique ports may be scanned")
    if not ports:
        raise ValueError("at least one port is required")
    return tuple(sorted(ports))


def _valid_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise ValueError("ports must be between 1 and 65535")
    return port


async def resolve_ipv4(target: str) -> str:
    """Resolve once and pin one IPv4 address for the complete scan."""

    try:
        return str(ipaddress.IPv4Address(target))
    except ipaddress.AddressValueError:
        pass
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise ValueError("target did not resolve to IPv4")
    return addresses[0]


class AuthorizedPortScanner:
    """TCP-connect scanner that refuses stale or target-mismatched authorization."""

    def __init__(self, authorization: AuthorizationContext) -> None:
        self.authorization = authorization

    async def scan(
        self,
        config: PortScanConfig,
        *,
        cancel: asyncio.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> PortScanReport:
        now = datetime.now(UTC)
        if not self.authorization.is_current(now):
            raise PermissionError("authorization is not current")
        if config.target != self.authorization.target:
            raise PermissionError("scan target does not match authorization")
        if config.method is not ScanMethod.TCP_CONNECT:
            raise ValueError("use PrivilegedSynScanner for SYN scanning")

        resolved = await resolve_ipv4(config.target)
        started = datetime.now(UTC)
        cancel_event = cancel or asyncio.Event()
        semaphore = asyncio.Semaphore(config.concurrency)
        interval = max(1 / config.max_attempts_per_second, config.minimum_interval_seconds)
        rate_lock = asyncio.Lock()
        next_start = 0.0

        async def scan_one(port: int) -> PortObservation:
            nonlocal next_start
            if cancel_event.is_set():
                return PortObservation(port, PortState.FILTERED, None, None, None)
            async with semaphore:
                async with rate_lock:
                    loop = asyncio.get_running_loop()
                    delay = max(0.0, next_start - loop.time())
                    if delay:
                        await asyncio.sleep(delay)
                    next_start = loop.time() + interval
                return await _connect_port(resolved, port, config)

        tasks = [asyncio.create_task(scan_one(port)) for port in config.ports]
        observations: list[PortObservation] = []
        try:
            for completed in asyncio.as_completed(tasks):
                if cancel_event.is_set():
                    break
                observation = await completed
                observations.append(observation)
                if progress is not None:
                    await progress(len(observations), len(config.ports), observation)
        finally:
            if cancel_event.is_set():
                for task in tasks:
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        observations.sort(key=lambda item: item.port)
        reachable = any(item.state in {PortState.OPEN, PortState.CLOSED} for item in observations)
        return PortScanReport(
            target=config.target,
            resolved_ipv4=resolved,
            method=config.method,
            started_at=started,
            completed_at=datetime.now(UTC),
            cancelled=cancel_event.is_set(),
            host_reachable=reachable,
            observations=tuple(observations),
        )


async def _connect_port(address: str, port: int, config: PortScanConfig) -> PortObservation:
    loop = asyncio.get_running_loop()
    started = loop.time()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=config.timeout_seconds
        )
        latency = round((loop.time() - started) * 1000, 2)
        banner = (
            await _read_banner(reader, config.timeout_seconds) if config.collect_banners else None
        )
        return PortObservation(
            port, PortState.OPEN, identify_service(port, banner), banner, latency
        )
    except ConnectionRefusedError:
        return PortObservation(port, PortState.CLOSED, identify_service(port, None), None, None)
    except TimeoutError:
        return PortObservation(port, PortState.FILTERED, identify_service(port, None), None, None)
    except OSError:
        return PortObservation(
            port, PortState.UNREACHABLE, identify_service(port, None), None, None
        )
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()


async def _read_banner(reader: asyncio.StreamReader, timeout: float) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 0.5))
    except TimeoutError:
        return None
    if not data:
        return None
    cleaned = "".join(
        character if character.isprintable() else " "
        for character in data.decode("utf-8", "replace")
    )
    return " ".join(cleaned.split())[:256] or None


def identify_service(port: int, banner: str | None) -> str | None:
    if banner:
        lowered = banner.casefold()
        indicators = (("ssh-", "ssh"), ("smtp", "smtp"), ("ftp", "ftp"), ("http/", "http"))
        for marker, service in indicators:
            if marker in lowered:
                return service
    return _SERVICE_BY_PORT.get(port)
