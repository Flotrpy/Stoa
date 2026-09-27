"""Desktop orchestration for authorized firewall policy simulation."""

from typing import Any, cast
from uuid import UUID

from stoa_desktop.session import DesktopSession
from stoa_security.firewall_simulator import (
    Action,
    SimulatedPacket,
    analyze_policy,
    evaluate_packet,
    generate_test_packets,
    import_policy,
)


class FirewallSimulatorService:
    def __init__(self, session: DesktopSession) -> None:
        self.session = session

    def options(self) -> dict[str, Any]:
        return {
            "endpoints": self.session.client.get("/api/v1/endpoints"),
            "scopes": self.session.client.get("/api/v1/authorization-scopes"),
        }

    def run(
        self,
        *,
        target: str,
        scope_id: UUID,
        justification: str,
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        endpoint_id = self.session.settings.endpoint_id
        if endpoint_id is None or self.session.principal is None:
            raise RuntimeError("connect and enroll this endpoint before simulating firewall rules")
        rules = import_policy(policy)
        default_action = cast(Action, policy.get("default_action", "block"))
        packets = [SimulatedPacket(**packet) for packet in policy.get("packets", [])] or list(
            generate_test_packets(rules)
        )
        configuration = {
            "default_action": default_action,
            "rules": policy["rules"],
            "packets": [
                {
                    "direction": packet.direction,
                    "protocol": packet.protocol,
                    "source": packet.source,
                    "destination": packet.destination,
                    "source_port": packet.source_port,
                    "destination_port": packet.destination_port,
                }
                for packet in packets
            ],
            "generate_test_packets": not policy.get("packets"),
        }
        job = cast(
            dict[str, Any],
            self.session.client.post(
                "/api/v1/jobs",
                {
                    "module_id": "firewall-simulator",
                    "executing_endpoint_id": str(endpoint_id),
                    "authorization_scope_id": str(scope_id),
                    "target": target,
                    "business_justification": justification,
                    "configuration": configuration,
                },
            ),
        )
        analysis = analyze_policy(rules)
        decisions = [
            evaluate_packet(rules, packet, default_action=default_action) for packet in packets
        ]
        result = self.session.client.post(
            f"/api/v1/jobs/{job['id']}/firewall-simulation-results",
            {
                "executing_endpoint_id": str(endpoint_id),
                "analysis": {
                    "shadowed_rules": list(analysis.shadowed_rules),
                    "conflicting_rules": list(analysis.conflicting_rules),
                },
                "observations": [
                    {
                        "packet": {
                            "direction": packet.direction,
                            "protocol": packet.protocol,
                            "source": packet.source,
                            "destination": packet.destination,
                            "source_port": packet.source_port,
                            "destination_port": packet.destination_port,
                        },
                        "action": decision.action,
                        "matched_rule": decision.matched_rule.name
                        if decision.matched_rule is not None
                        else None,
                        "explanation": decision.explanation,
                    }
                    for packet, decision in zip(packets, decisions, strict=True)
                ],
            },
        )
        return cast(dict[str, Any], result)
