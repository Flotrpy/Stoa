# Authorized port and service scanner

PR 4 delivers Stoá's first complete security-module workflow. It is intended only for assets covered by a current central authorization scope.

## Workflow and enforcement

1. An administrator approves an endpoint and enables the `port-scanner` module policy.
2. A scope names the exact target or IPv4 network, allowed module, validity window, and request budget.
3. The desktop selects that scope, supplies a business justification, and requests a job.
4. The API rechecks current membership, endpoint approval, scope, target, module, policy, port count, concurrency, banner policy, method, and effective rate interval.
5. The endpoint constructs an immutable authorization context from the accepted job. The worker refuses stale or target-mismatched contexts.
6. Structured observations return to the central API bound to the job's executing endpoint. The API finalizes the job and records a redacted audit event.

## Scan behavior

- TCP connect is the normal unprivileged method.
- Inputs support single ports, ascending ranges of at most 1,024 ports, and the reviewed `web`, `remote-admin`, `databases`, and `common` presets.
- Hostnames resolve once to one IPv4 address, which remains pinned for the scan.
- Open, closed, filtered, and unreachable states are explicit. Firewall and operating-system behavior can make a closed port appear filtered.
- Banner collection never sends a protocol probe. It reads at most 512 bytes for at most 500 ms, converts control characters to spaces, and persists at most 256 printable characters.
- Service names are heuristic, based on a small conventional-port map and a few recognizable banner markers.
- Cancellation stops scheduling useful work, cancels outstanding TCP tasks, and records the job as cancelled.

The optional SYN adapter uses Scapy 2.7.0. It requires central `allow_syn` policy, a separate explicit local privilege confirmation, and platform packet-capture support such as Npcap on Windows. It uses the endpoint's actual source address and sends a reset after SYN-ACK. Stoá provides no stealth, evasion, decoy, spoofing, fragmentation, flood, or denial-of-service settings.

## Reports and fixtures

The UI shows progress and structured results and exports server-generated JSON or human-readable text. Automated tests use only loopback listeners with a deterministic synthetic SSH banner; they never contact public targets.
