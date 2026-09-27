"""Explainable firewall policy simulation without host firewall mutation."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from stoa_security.packet_analysis import PacketMetadata

Direction = Literal["inbound", "outbound"]
Protocol = Literal["tcp", "udp", "icmp", "any"]
Action = Literal["allow", "block"]


@dataclass(frozen=True, slots=True)
class PortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if not 1 <= self.start <= self.end <= 65535:
            raise ValueError("ports must be between 1 and 65535")

    def contains(self, port: int | None) -> bool:
        return port is not None and self.start <= port <= self.end

    def overlaps(self, other: PortRange) -> bool:
        return self.start <= other.end and other.start <= self.end


@dataclass(frozen=True, slots=True)
class FirewallRule:
    order: int
    name: str
    direction: Direction
    action: Action
    protocol: Protocol = "any"
    source: str = "0.0.0.0/0"
    destination: str = "0.0.0.0/0"
    source_ports: tuple[PortRange, ...] = ()
    destination_ports: tuple[PortRange, ...] = ()
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.order < 1:
            raise ValueError("rule order must be positive")
        if not self.name.strip() or len(self.name) > 160:
            raise ValueError("rule name must be between 1 and 160 characters")
        ip_network(self.source, strict=False)
        ip_network(self.destination, strict=False)
        if self.protocol in {"icmp", "any"} and (self.source_ports or self.destination_ports):
            raise ValueError("ports can only be set for TCP or UDP rules")


@dataclass(frozen=True, slots=True)
class SimulatedPacket:
    direction: Direction
    protocol: Protocol
    source: str
    destination: str
    source_port: int | None = None
    destination_port: int | None = None

    def __post_init__(self) -> None:
        ip_address(self.source)
        ip_address(self.destination)
        if self.protocol in {"tcp", "udp"}:
            for port in (self.source_port, self.destination_port):
                if port is not None and not 1 <= port <= 65535:
                    raise ValueError("packet ports must be between 1 and 65535")
        if self.protocol == "icmp" and (
            self.source_port is not None or self.destination_port is not None
        ):
            raise ValueError("ICMP packets cannot have ports")


@dataclass(frozen=True, slots=True)
class SimulationDecision:
    action: Action
    matched_rule: FirewallRule | None
    explanation: str
    evaluated_rules: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicyAnalysis:
    shadowed_rules: tuple[dict[str, str | int], ...]
    conflicting_rules: tuple[dict[str, str | int], ...]


def evaluate_packet(
    rules: tuple[FirewallRule, ...], packet: SimulatedPacket, *, default_action: Action = "block"
) -> SimulationDecision:
    reasons: list[str] = []
    for count, rule in enumerate(sorted(rules, key=lambda item: item.order), start=1):
        if not rule.enabled:
            reasons.append(f"{rule.name}: skipped disabled rule")
            continue
        matched, reason = _rule_matches(rule, packet)
        reasons.append(f"{rule.name}: {reason}")
        if matched:
            return SimulationDecision(
                action=rule.action,
                matched_rule=rule,
                explanation=(
                    f"Rule {rule.order} '{rule.name}' is the first match and {rule.action}s "
                    "the packet."
                ),
                evaluated_rules=count,
                reasons=tuple(reasons),
            )
    return SimulationDecision(
        action=default_action,
        matched_rule=None,
        explanation=f"No enabled rule matched; default policy {default_action}s the packet.",
        evaluated_rules=len(rules),
        reasons=tuple(reasons),
    )


def analyze_policy(rules: tuple[FirewallRule, ...]) -> PolicyAnalysis:
    ordered = tuple(sorted((rule for rule in rules if rule.enabled), key=lambda item: item.order))
    shadowed: list[dict[str, str | int]] = []
    conflicts: list[dict[str, str | int]] = []
    for index, rule in enumerate(ordered):
        for earlier in ordered[:index]:
            if _rule_covers(earlier, rule):
                shadowed.append(
                    {
                        "rule": rule.order,
                        "shadowed_by": earlier.order,
                        "reason": "an earlier enabled rule covers every packet this rule can match",
                    }
                )
                break
            if earlier.action != rule.action and _rules_overlap(earlier, rule):
                conflicts.append(
                    {
                        "rule": rule.order,
                        "conflicts_with": earlier.order,
                        "reason": "rules overlap but take different actions; first match wins",
                    }
                )
    return PolicyAnalysis(tuple(shadowed), tuple(conflicts))


def generate_test_packets(rules: tuple[FirewallRule, ...]) -> tuple[SimulatedPacket, ...]:
    packets: list[SimulatedPacket] = []
    for rule in sorted(rules, key=lambda item: item.order):
        if not rule.enabled:
            continue
        protocol: Protocol = "tcp" if rule.protocol == "any" else rule.protocol
        source_port = _first_port(rule.source_ports) if protocol in {"tcp", "udp"} else None
        destination_port = (
            _first_port(rule.destination_ports) if protocol in {"tcp", "udp"} else None
        )
        packets.append(
            SimulatedPacket(
                direction=rule.direction,
                protocol=protocol,
                source=_representative_ip(rule.source),
                destination=_representative_ip(rule.destination),
                source_port=source_port or (49152 if protocol in {"tcp", "udp"} else None),
                destination_port=destination_port or (443 if protocol in {"tcp", "udp"} else None),
            )
        )
    return tuple(packets)


def packet_from_metadata(
    metadata: PacketMetadata, *, direction: Direction
) -> SimulatedPacket | None:
    if (
        metadata.protocol not in {"tcp", "udp", "icmp"}
        or not metadata.source
        or not metadata.destination
    ):
        return None
    protocol: Protocol = "icmp" if metadata.protocol == "icmp" else metadata.protocol  # type: ignore[assignment]
    return SimulatedPacket(
        direction=direction,
        protocol=protocol,
        source=metadata.source,
        destination=metadata.destination,
        source_port=metadata.source_port,
        destination_port=metadata.destination_port,
    )


def import_policy(payload: dict[str, Any]) -> tuple[FirewallRule, ...]:
    return tuple(_rule_from_dict(item) for item in payload.get("rules", []))


def export_policy(rules: tuple[FirewallRule, ...], *, default_action: Action) -> dict[str, Any]:
    return {
        "default_action": default_action,
        "rules": [
            {
                "order": rule.order,
                "name": rule.name,
                "direction": rule.direction,
                "action": rule.action,
                "protocol": rule.protocol,
                "source": rule.source,
                "destination": rule.destination,
                "source_ports": [[item.start, item.end] for item in rule.source_ports],
                "destination_ports": [[item.start, item.end] for item in rule.destination_ports],
                "enabled": rule.enabled,
            }
            for rule in sorted(rules, key=lambda item: item.order)
        ],
    }


def _rule_from_dict(item: dict[str, Any]) -> FirewallRule:
    return FirewallRule(
        order=int(item["order"]),
        name=str(item["name"]),
        direction=item["direction"],
        action=item["action"],
        protocol=item.get("protocol", "any"),
        source=item.get("source", "0.0.0.0/0"),
        destination=item.get("destination", "0.0.0.0/0"),
        source_ports=tuple(
            PortRange(int(start), int(end)) for start, end in item.get("source_ports", [])
        ),
        destination_ports=tuple(
            PortRange(int(start), int(end)) for start, end in item.get("destination_ports", [])
        ),
        enabled=bool(item.get("enabled", True)),
    )


def _rule_matches(rule: FirewallRule, packet: SimulatedPacket) -> tuple[bool, str]:
    if rule.direction != packet.direction:
        return False, "direction differs"
    if rule.protocol != "any" and rule.protocol != packet.protocol:
        return False, "protocol differs"
    if ip_address(packet.source) not in ip_network(rule.source, strict=False):
        return False, "source address outside rule source CIDR"
    if ip_address(packet.destination) not in ip_network(rule.destination, strict=False):
        return False, "destination address outside rule destination CIDR"
    if not _ports_match(rule.source_ports, packet.source_port):
        return False, "source port outside rule range"
    if not _ports_match(rule.destination_ports, packet.destination_port):
        return False, "destination port outside rule range"
    return True, "all match criteria satisfied"


def _ports_match(ranges: tuple[PortRange, ...], port: int | None) -> bool:
    return not ranges or any(item.contains(port) for item in ranges)


def _rule_covers(earlier: FirewallRule, later: FirewallRule) -> bool:
    return (
        earlier.direction == later.direction
        and _protocol_covers(earlier.protocol, later.protocol)
        and _subnet_of(later.source, earlier.source)
        and _subnet_of(later.destination, earlier.destination)
        and _ranges_cover(earlier.source_ports, later.source_ports)
        and _ranges_cover(earlier.destination_ports, later.destination_ports)
    )


def _rules_overlap(first: FirewallRule, second: FirewallRule) -> bool:
    return (
        first.direction == second.direction
        and _protocols_overlap(first.protocol, second.protocol)
        and ip_network(first.source, strict=False).overlaps(ip_network(second.source, strict=False))
        and ip_network(first.destination, strict=False).overlaps(
            ip_network(second.destination, strict=False)
        )
        and _ranges_overlap(first.source_ports, second.source_ports)
        and _ranges_overlap(first.destination_ports, second.destination_ports)
    )


def _protocol_covers(first: Protocol, second: Protocol) -> bool:
    return first == "any" or first == second


def _protocols_overlap(first: Protocol, second: Protocol) -> bool:
    return first == "any" or second == "any" or first == second


def _subnet_of(child: str, parent: str) -> bool:
    child_network = ip_network(child, strict=False)
    parent_network = ip_network(parent, strict=False)
    return child_network.version == parent_network.version and child_network.subnet_of(
        parent_network  # type: ignore[arg-type]
    )


def _ranges_cover(first: tuple[PortRange, ...], second: tuple[PortRange, ...]) -> bool:
    if not first:
        return True
    if not second:
        return False
    return all(any(a.start <= b.start and b.end <= a.end for a in first) for b in second)


def _ranges_overlap(first: tuple[PortRange, ...], second: tuple[PortRange, ...]) -> bool:
    if not first or not second:
        return True
    return any(a.overlaps(b) for a in first for b in second)


def _first_port(ranges: tuple[PortRange, ...]) -> int | None:
    return ranges[0].start if ranges else None


def _representative_ip(network_text: str) -> str:
    network = ip_network(network_text, strict=False)
    return str(next(iter(network.hosts()), network.network_address))
