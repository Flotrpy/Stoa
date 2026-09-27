from datetime import UTC, datetime

import pytest

from stoa_security.firewall_simulator import (
    FirewallRule,
    PortRange,
    SimulatedPacket,
    analyze_policy,
    evaluate_packet,
    export_policy,
    generate_test_packets,
    import_policy,
    packet_from_metadata,
)
from stoa_security.packet_analysis import PacketMetadata


def test_firewall_first_match_default_and_explanations() -> None:
    rules = (
        FirewallRule(
            order=1,
            name="Allow web",
            direction="outbound",
            action="allow",
            protocol="tcp",
            source="192.0.2.0/24",
            destination="198.51.100.10/32",
            destination_ports=(PortRange(443, 443),),
        ),
        FirewallRule(
            order=2,
            name="Block all outbound",
            direction="outbound",
            action="block",
        ),
    )
    allowed = evaluate_packet(
        rules,
        SimulatedPacket(
            direction="outbound",
            protocol="tcp",
            source="192.0.2.15",
            destination="198.51.100.10",
            source_port=50000,
            destination_port=443,
        ),
    )
    defaulted = evaluate_packet(
        rules,
        SimulatedPacket(
            direction="inbound",
            protocol="icmp",
            source="198.51.100.10",
            destination="192.0.2.15",
        ),
    )

    assert allowed.action == "allow"
    assert allowed.matched_rule is rules[0]
    assert "first match" in allowed.explanation
    assert defaulted.action == "block"
    assert "default policy" in defaulted.explanation


def test_firewall_analysis_import_export_generation_and_replay() -> None:
    payload = {
        "default_action": "block",
        "rules": [
            {
                "order": 1,
                "name": "Block lab",
                "direction": "outbound",
                "action": "block",
                "source": "192.0.2.0/24",
                "destination": "0.0.0.0/0",
            },
            {
                "order": 2,
                "name": "Allow HTTPS host",
                "direction": "outbound",
                "action": "allow",
                "protocol": "tcp",
                "source": "192.0.2.10/32",
                "destination": "198.51.100.10/32",
                "destination_ports": [[443, 443]],
            },
        ],
    }
    rules = import_policy(payload)
    analysis = analyze_policy(rules)
    packets = generate_test_packets(rules)
    metadata_packet = packet_from_metadata(
        PacketMetadata(
            datetime.now(UTC),
            60,
            "tcp",
            "192.0.2.10",
            "198.51.100.10",
            50000,
            443,
        ),
        direction="outbound",
    )

    assert analysis.shadowed_rules[0]["rule"] == 2
    assert analysis.conflicting_rules == ()
    assert packets[0].direction == "outbound"
    assert metadata_packet is not None
    assert metadata_packet.destination_port == 443
    assert export_policy(rules, default_action="block")["rules"][1]["destination_ports"] == [
        [443, 443]
    ]
    with pytest.raises(ValueError):
        FirewallRule(
            order=1,
            name="Bad ICMP",
            direction="inbound",
            action="allow",
            protocol="icmp",
            destination_ports=(PortRange(8, 8),),
        )
