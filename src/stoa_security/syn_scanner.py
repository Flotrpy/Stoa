"""Explicitly authorized privileged SYN scanning adapter."""

import asyncio
import time
from datetime import UTC, datetime

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sr1

from stoa_security.contracts import AuthorizationContext
from stoa_security.port_scanner import (
    PortObservation,
    PortScanConfig,
    PortScanReport,
    PortState,
    ScanMethod,
    identify_service,
    resolve_ipv4,
)


class PrivilegedSynScanner:
    """Run a non-spoofed SYN scan only after an explicit privileged opt-in."""

    def __init__(self, authorization: AuthorizationContext, *, privilege_confirmed: bool) -> None:
        if not privilege_confirmed:
            raise PermissionError("SYN scanning requires explicit privileged-mode confirmation")
        self.authorization = authorization

    async def scan(
        self, config: PortScanConfig, *, cancel: asyncio.Event | None = None
    ) -> PortScanReport:
        now = datetime.now(UTC)
        if not self.authorization.is_current(now):
            raise PermissionError("authorization is not current")
        if config.target != self.authorization.target:
            raise PermissionError("scan target does not match authorization")
        if config.method is not ScanMethod.SYN:
            raise ValueError("SYN scanner requires the syn method")

        resolved = await resolve_ipv4(config.target)
        started = datetime.now(UTC)
        cancel_event = cancel or asyncio.Event()
        observations: list[PortObservation] = []
        interval = 1 / config.max_attempts_per_second
        for port in config.ports:
            if cancel_event.is_set():
                break
            observation = await asyncio.to_thread(
                self._probe, resolved, port, config.timeout_seconds
            )
            observations.append(observation)
            await asyncio.sleep(interval)
        return PortScanReport(
            target=config.target,
            resolved_ipv4=resolved,
            method=config.method,
            started_at=started,
            completed_at=datetime.now(UTC),
            cancelled=cancel_event.is_set(),
            host_reachable=any(
                item.state in {PortState.OPEN, PortState.CLOSED} for item in observations
            ),
            observations=tuple(observations),
        )

    @staticmethod
    def _probe(address: str, port: int, timeout: float) -> PortObservation:
        started = time.monotonic()
        response = sr1(
            IP(dst=address) / TCP(dport=port, flags="S"),
            timeout=timeout,
            verbose=False,
        )
        latency = round((time.monotonic() - started) * 1000, 2)
        if response is None:
            return PortObservation(
                port, PortState.FILTERED, identify_service(port, None), None, None
            )
        tcp = response.getlayer(TCP)
        if tcp is not None and int(tcp.flags) & 0x12 == 0x12:
            send(IP(dst=address) / TCP(dport=port, flags="R"), verbose=False)
            return PortObservation(
                port, PortState.OPEN, identify_service(port, None), None, latency
            )
        if tcp is not None and int(tcp.flags) & 0x04:
            return PortObservation(
                port, PortState.CLOSED, identify_service(port, None), None, latency
            )
        return PortObservation(
            port, PortState.UNREACHABLE, identify_service(port, None), None, latency
        )
