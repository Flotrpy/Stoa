# Packet analysis and IDS

PR 5 keeps sensitive network evidence on the endpoint while coordinating authorization and redacted alerts centrally.

- Live capture requires an approved endpoint, current `packet-analysis` scope, enabled policy, interface choice, and business justification.
- The scope network is applied before any frame is written to the rotating local PCAP store.
- Views cover TCP, UDP, ICMP, ARP, DNS, HTTP request metadata, and TLS record-version metadata. Raw payload bytes are discarded after local extraction.
- Search, protocol filtering, packet/byte counts, top endpoints, bounded PCAP replay, and explicit Wireshark-compatible export are local operations.
- Four deterministic rules flag rapid multi-port attempts, ARP binding changes, high-entropy DNS labels, and conventionally cleartext service ports. Each documents confidence and false-positive causes.
- Central submission creates deduplicated alert metadata and explanatory findings; it has no PCAP or raw-payload field.

Windows live capture requires a working Npcap installation. Linux requires capture capabilities or an appropriately permissioned helper. Stoá does not elevate the entire desktop application.
