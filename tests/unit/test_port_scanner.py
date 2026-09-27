import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from stoa_security.contracts import AuthorizationContext
from stoa_security.port_scanner import (
    AuthorizedPortScanner,
    PortObservation,
    PortScanConfig,
    PortState,
    ScanMethod,
    identify_service,
    parse_ports,
    resolve_ipv4,
)
from stoa_security.syn_scanner import PrivilegedSynScanner


def authorization(target: str, *, current: bool = True) -> AuthorizationContext:
    now = datetime.now(UTC)
    return AuthorizationContext(
        scope_id=uuid4(),
        requesting_user_id=uuid4(),
        executing_endpoint_id=uuid4(),
        target=target,
        valid_from=now - timedelta(minutes=1 if current else 10),
        expires_at=now + timedelta(minutes=10) if current else now - timedelta(minutes=1),
        business_justification="Verify the explicitly authorized local lab service inventory",
        correlation_id=uuid4(),
    )


def test_port_parser_supports_ranges_and_approved_presets() -> None:
    assert parse_ports("22, 80-82, web") == (22, 80, 81, 82, 443, 8000, 8080, 8443)
    for invalid in ("", "80,,443", "0", "65536", "90-80", "1-1025", "stealth"):
        with pytest.raises(ValueError):
            parse_ports(invalid)


def test_scan_configuration_is_strictly_bounded() -> None:
    with pytest.raises(ValueError, match="unique and sorted"):
        PortScanConfig("127.0.0.1", (443, 80))
    with pytest.raises(ValueError, match="concurrency"):
        PortScanConfig("127.0.0.1", (80,), concurrency=0)
    with pytest.raises(ValueError, match="rate"):
        PortScanConfig("127.0.0.1", (80,), max_attempts_per_second=1000)


@pytest.mark.asyncio
async def test_tcp_connect_scan_detects_safe_local_banner_and_closed_port() -> None:
    async def banner_service(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        writer.write(b"SSH-2.0-Stoa-Safe-Fixture\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(banner_service, "127.0.0.1", 0)
    open_port = int(server.sockets[0].getsockname()[1])
    temporary = await asyncio.start_server(banner_service, "127.0.0.1", 0)
    closed_port = int(temporary.sockets[0].getsockname()[1])
    temporary.close()
    await temporary.wait_closed()
    ports = tuple(sorted((open_port, closed_port)))
    report = await AuthorizedPortScanner(authorization("127.0.0.1")).scan(
        PortScanConfig(
            target="127.0.0.1",
            ports=ports,
            timeout_seconds=0.5,
            max_attempts_per_second=500,
        )
    )
    server.close()
    await server.wait_closed()

    results = {item.port: item for item in report.observations}
    assert results[open_port].state is PortState.OPEN
    assert results[open_port].service == "ssh"
    assert results[open_port].banner == "SSH-2.0-Stoa-Safe-Fixture"
    assert results[closed_port].state in {PortState.CLOSED, PortState.FILTERED}
    assert report.host_reachable is True
    assert report.as_json()["method"] == "tcp-connect"
    assert "PORT" in report.as_text()


@pytest.mark.asyncio
async def test_scan_fails_closed_on_authorization_mismatch_or_expiry() -> None:
    config = PortScanConfig("127.0.0.1", (80,))
    with pytest.raises(PermissionError, match="does not match"):
        await AuthorizedPortScanner(authorization("127.0.0.2")).scan(config)
    with pytest.raises(PermissionError, match="not current"):
        await AuthorizedPortScanner(authorization("127.0.0.1", current=False)).scan(config)
    with pytest.raises(PermissionError, match="confirmation"):
        PrivilegedSynScanner(authorization("127.0.0.1"), privilege_confirmed=False)


@pytest.mark.asyncio
async def test_resolution_and_service_identification_are_deterministic() -> None:
    assert await resolve_ipv4("127.0.0.1") == "127.0.0.1"
    assert identify_service(443, None) == "https"
    assert identify_service(65000, "HTTP/1.1 200 OK") == "http"
    assert identify_service(65000, None) is None


@pytest.mark.asyncio
async def test_syn_scanner_requires_matching_method_and_supports_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = PrivilegedSynScanner(authorization("127.0.0.1"), privilege_confirmed=True)

    def probe(address: str, port: int, timeout: float) -> PortObservation:
        assert address == "127.0.0.1"
        assert timeout == 0.1
        return PortObservation(port, PortState.CLOSED, None, None, 1.0)

    monkeypatch.setattr(scanner, "_probe", probe)
    report = await scanner.scan(
        PortScanConfig(
            "127.0.0.1",
            (80,),
            method=ScanMethod.SYN,
            timeout_seconds=0.1,
            max_attempts_per_second=500,
        )
    )
    assert report.observations[0].state is PortState.CLOSED
    assert report.host_reachable is True

    cancelled = asyncio.Event()
    cancelled.set()
    report = await scanner.scan(
        PortScanConfig("127.0.0.1", (80,), method=ScanMethod.SYN), cancel=cancelled
    )
    assert report.cancelled is True
    assert report.observations == ()

    with pytest.raises(ValueError, match="requires the syn method"):
        await scanner.scan(PortScanConfig("127.0.0.1", (80,)))
