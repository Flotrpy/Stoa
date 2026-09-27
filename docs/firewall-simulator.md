# Firewall simulator

PR 7 adds an explainable firewall policy simulator. It evaluates proposed rules and packets only; it never changes Windows Firewall, nftables, iptables, pf, or any host network setting.

## Rule model

- Rules are ordered and evaluated with first-match semantics.
- Each rule supports inbound or outbound direction, allow or block action, TCP, UDP, ICMP, or any protocol, source and destination CIDR ranges, and optional TCP/UDP source and destination port ranges.
- If no enabled rule matches, the configured default action is used.
- Explanations record which rule matched, why earlier rules did not match, and when the default policy was used.

## Analysis

The analyzer reports:

- Shadowed rules: an earlier enabled rule covers every packet a later rule could match.
- Conflicting rules: two enabled rules overlap but take different actions; first match still decides runtime behavior.
- Generated packets: representative packets derived from enabled rules for quick validation.
- Replay: TCP, UDP, and ICMP packet metadata can be converted into simulated packets without requiring raw payloads.

## Central boundaries

The API authorizes `firewall-simulator` jobs against current endpoint, scope, module, and policy records. It stores simulation decisions and explanations, not operating-system firewall state. Reports are generated centrally as JSON or text.
