# Delivery status

Updated: 2026-09-27

## Current phase

PR 1 — Foundation: open, green, and awaiting review.

PR 2 — Identity and shared platform: open, green, and awaiting review.

PR 3 — Desktop foundation: open, green, and awaiting review.

PR 4 — Port and service scanner: open, green, and awaiting review.

PR 5 — Packet analysis and IDS: open, green, and awaiting review.

PR 6 — Web security scanner: open, green, and awaiting review.

PR 7 — Firewall simulator: open, green, and awaiting review.

PR 8 — Endpoint monitoring: implementation complete locally on a stacked branch and undergoing final verification.

## Repository inspection

- Starting state: empty Git repository on `master`, no commits, no configured remote.
- GitHub authentication: active account `Flotrpy` over HTTPS.
- Local tools: Git 2.54, GitHub CLI 2.101, Node 24.13.1, npm 11.16.0, Python 3.12.10.
- Missing global prerequisites: Docker/Compose, Python launcher (`py`), Ruff, mypy, pytest, and Bandit. Python tools are intentionally installed into `.venv` by `npm run setup`; Docker remains an explicit external prerequisite.
- Existing user work: none found.

## Scope truth

Foundation, central identity/authorization, and desktop connection capabilities are implemented on stacked, unmerged branches. Security modules, secure chat, native installers, and production operations remain scheduled for PRs 4–10. Disabled future navigation items identify the planned information architecture without pretending those workflows exist.

PR 2 now implements the central identity and authorization layer, but it is not yet merged. Security-module execution remains absent; only authorization-gated job metadata can be queued.

PR 3 adds first-run connection, secure token storage, endpoint enrollment, background API work, authenticated realtime transport, crash-safe local preferences, safe offline metadata queueing, explicit connectivity state, settings, and light/dark themes. It stores no passwords, raw evidence, capture data, private keys, or plaintext chat.

PR 4 implements bounded TCP-connect scanning and an explicitly privileged SYN adapter, pinned IPv4 resolution, cancellation, progress, safe receive-only banners, service identification, central policy enforcement, structured observations, JSON/text reports, and the first complete module workflow. Stealth, evasion, address spoofing, exploit delivery, and denial-of-service options are absent.

PR 5 implements authorized interface capture, protocol metadata views, local rotating PCAP retention/export, deterministic replay, search/filter/summaries, explainable deterministic IDS rules, redacted alerts, and explicit capture-permission failures. Packet payloads and PCAP bytes never enter central API schemas.

PR 6 implements same-origin crawling, URL/link/form/input/cookie/header/parameter discovery, passive header/cookie checks, bounded canary-based active indicators, optional local ZAP metadata import, central policy enforcement, redacted findings, JSON/text reports, and a desktop workflow. It does not perform cross-origin scanning, exploit delivery, credential attacks, time-delay SQL probes, or broad broken-authentication claims.

PR 7 implements ordered allow/block simulation, TCP/UDP/ICMP/any matching, source/destination CIDR and port ranges, first-match decisions, default policy, validation, shadow/conflict analysis, generated packets, packet-metadata replay, import/export, central reports, and a desktop workflow. It never mutates host firewall configuration.

PR 8 implements local SHA-256 baselines, include/exclude and recursion controls, large-file handling, file lifecycle and rename detection, tamper-evident event chains, baseline renewal, bounded central observations, deduplicated alerts, reports, and non-invasive Windows/Linux process-metadata indicators. It never captures keystrokes or file contents.

## Verification evidence

- `npm install`: passed; npm dependency audit reported zero findings.
- `npm run setup`: passed with Python 3.12.10 and an isolated `.venv`.
- PR 1 `npm run build`: passed formatting, Ruff, strict mypy, 13 tests, 83.19% coverage, Bandit, pip-audit with zero known vulnerabilities, secret scanning, wheel/sdist creation, and artifact validation.
- PR 2 hosted workflow: passed Windows, Ubuntu, Compose validation, and PostgreSQL migration lifecycle checks.
- PR 3 `npm run build`: passed formatting, Ruff, strict mypy, 41 tests at 81.62% coverage, Bandit, dependency audit, secret scan, source/wheel builds, and packaging validation.
- PR 3 hosted workflow: passed Windows, Ubuntu, Compose validation, and PostgreSQL migration lifecycle checks.
- PR 4 `npm run build`: passed formatting, Ruff, strict mypy, 49 tests at 78.16% coverage, Bandit, dependency audit, secret scan, source/wheel builds, and packaging validation.
- PR 4 hosted workflow: passed Windows, Ubuntu, Compose validation, and PostgreSQL migration lifecycle checks.
- PR 5 `npm run build`: passed formatting, Ruff, strict mypy, 55 tests at 76.51% coverage, Bandit, dependency audit, secret scan, source/wheel builds, and packaging validation.
- PR 5 Windows CI repair: replaced implicit Scapy Ethernet fixture addressing with explicit synthetic MAC addresses after hosted Windows lacked the default loopback adapter name.
- PR 5 hosted workflow: passed Windows, Ubuntu, Compose validation, and PostgreSQL migration lifecycle checks.
- PR 6 focused tests: passed web scanner unit tests, API job/report tests, desktop smoke, and migration cycle; subset coverage gate is expected to fail when only focused tests run.
- PR 6 `npm run build`: passed formatting, Ruff, strict mypy, 58 tests at 76.81% coverage, Bandit, dependency audit, secret scan, source/wheel builds, and packaging validation.
- PR 6 hosted workflow: passed Windows, Ubuntu, Compose validation, and PostgreSQL migration lifecycle checks.
- PR 7 focused tests: passed firewall simulator unit tests, API job/report tests, desktop smoke, and migration cycle; subset coverage gate is expected to fail when only focused tests run.
- PR 7 `npm run build`: passed formatting, Ruff, strict mypy, 61 tests at 76.13% coverage, Bandit, dependency audit, secret scan, source/wheel builds, and packaging validation.
- PR 7 hosted workflow: passed Windows, Ubuntu, Compose validation, and PostgreSQL migration lifecycle checks.
- PR 8 focused tests: passed endpoint-monitoring unit tests, API job/report tests, desktop smoke, and migration cycle.
- PR 8 `npm run build`: passed formatting, Ruff, strict mypy, 66 tests at 76.57% coverage, Bandit, dependency audit, secret scan, source/wheel builds, and packaging validation.
- Docker Compose model validation: passed in hosted CI. Local runtime validation remains unavailable because Docker is not installed on the current workstation.
- Windows verification: passed locally and in hosted CI. Linux verification: passed in hosted CI after declaring the required `libegl1` desktop runtime package.

## Major delivery risks

- The complete product is substantially larger than one review cycle; safety and quality require the ten-PR sequence in `PLAN.md`.
- Packet capture, raw sockets, signature verification, and native packaging differ materially between Windows and Linux and require dedicated test hosts.
- Active scanners require centralized authorization enforcement before they are safe to ship.
- End-to-end encrypted chat requires an established protocol/library choice and an independent professional cryptographic review.
- Reproducible signed installers require protected signing identities and CI secrets that are not available in a source checkout.
- Dependency auditing may expose upstream issues; releases cannot waive unexplained high-severity findings.
- Docker is unavailable on the current workstation, so Compose validation must be completed in CI or on a Docker-enabled host.
- The requirement for 100 meaningful commits is a target, not permission to fragment work artificially; the ledger will report any responsible shortfall.
