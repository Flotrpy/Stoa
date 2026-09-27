from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from stoa_security.ids import MetadataIds
from stoa_security.packet_analysis import (
    PacketMetadata,
    RotatingPcapStore,
    dns_entropy,
    filter_metadata,
    packet_metadata,
    replay_pcap,
    summarize,
)
from stoa_security.packet_capture import CaptureConfig


def test_protocol_metadata_views_exclude_raw_payloads() -> None:
    http = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=51000, dport=80)
    http /= Raw(b"GET /health HTTP/1.1\r\nHost: lab.example\r\n\r\nsecret-body")
    dns = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.test"))
    )
    tls = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=51001, dport=443)
        / Raw(bytes([22, 3, 3, 0, 0]))
    )
    icmp = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / ICMP()
    arp = Ether(src="00:11:22:33:44:55") / ARP(psrc="192.0.2.1", pdst="192.0.2.2", op=1)
    rows = [packet_metadata(packet) for packet in (http, dns, tls, icmp, arp)]

    assert rows[0].protocol == "http"
    assert rows[0].http_method == "GET"
    assert rows[0].http_host == "lab.example"
    assert rows[0].http_path == "/health"
    assert "secret-body" not in str(rows[0].as_dict())
    assert rows[1].protocol == "dns"
    assert rows[1].dns_query == "example.test"
    assert rows[2].protocol == "tls"
    assert rows[2].tls_version == "TLS1.2"
    assert rows[3].protocol == "icmp"
    assert rows[4].protocol == "arp"
    assert rows[4].arp_operation == "request"


def test_search_filter_and_traffic_summary() -> None:
    now = datetime.now(UTC)
    rows = [
        PacketMetadata(now, 100, "tcp", "192.0.2.1", "192.0.2.2", 50000, 443),
        PacketMetadata(now, 50, "dns", "192.0.2.1", "192.0.2.53", 50001, 53),
    ]
    summary = summarize(rows)

    assert summary.packet_count == 2
    assert summary.byte_count == 150
    assert summary.protocols == {"tcp": 1, "dns": 1}
    assert len(filter_metadata(rows, protocol="tcp")) == 1
    assert len(filter_metadata(rows, search="192.0.2.53")) == 1


def test_local_pcap_round_trip_rotation_and_explicit_export(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    store = RotatingPcapStore(managed, maximum_file_bytes=1000, retained_files=2)
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="127.0.0.1", dst="127.0.0.1")
        / TCP(sport=50000, dport=80)
    )
    source = store.write(packet)
    store.close()

    replayed = list(replay_pcap(source))
    assert len(replayed) == 1
    assert replayed[0].destination_port == 80
    destination = tmp_path / "export" / "wireshark.pcap"
    assert store.export(source, destination) == destination
    assert destination.read_bytes() == source.read_bytes()
    with pytest.raises(ValueError, match="managed"):
        store.export(tmp_path / "outside.pcap", destination)
    with pytest.raises(ValueError, match="replay limit"):
        list(replay_pcap(source, limit=0))


def test_ids_rules_are_deterministic_and_explain_false_positives() -> None:
    ids = MetadataIds(port_scan_threshold=5, port_scan_window_seconds=10)
    now = datetime.now(UTC)
    indicators = []
    for offset, port in enumerate((20, 21, 22, 23, 24)):
        indicators.extend(
            ids.inspect(
                PacketMetadata(
                    now + timedelta(milliseconds=offset),
                    60,
                    "tcp",
                    "192.0.2.10",
                    "192.0.2.20",
                    50000,
                    port,
                    "S",
                )
            )
        )
    arp_first = PacketMetadata(
        now, 60, "arp", "192.0.2.1", "192.0.2.2", source_mac="00:11:22:33:44:55"
    )
    arp_changed = PacketMetadata(
        now, 60, "arp", "192.0.2.1", "192.0.2.2", source_mac="00:11:22:33:44:66"
    )
    ids.inspect(arp_first)
    indicators.extend(ids.inspect(arp_changed))
    indicators.extend(
        ids.inspect(
            PacketMetadata(
                now,
                100,
                "dns",
                "192.0.2.10",
                "192.0.2.53",
                dns_query="a8x2q9z7m4k1p6v3n5r0.example",
            )
        )
    )
    indicators.extend(
        ids.inspect(PacketMetadata(now, 60, "tcp", "192.0.2.1", "192.0.2.2", 50000, 23))
    )

    rule_ids = {indicator.rule_id for indicator in indicators}
    assert {"STOA-NET-001", "STOA-NET-002", "STOA-NET-003", "STOA-NET-004"} <= rule_ids
    assert all(
        any(word in item.explanation.casefold() for word in ("can", "commonly", "do not"))
        for item in indicators
    )
    assert dns_entropy("aaaaaaaa") == 0.0


def test_capture_configuration_rejects_unbounded_or_unknown_filters() -> None:
    with pytest.raises(ValueError):
        CaptureConfig(
            interface="eth0",
            allowed_networks=("192.0.2.0/24",),
            protocols=frozenset({"payload"}),
        )
    with pytest.raises(ValueError):
        CaptureConfig(interface="eth0", allowed_networks=("192.0.2.0/24",), packet_limit=0)
