# Stoá — Unified Team Security Platform

You are the lead engineer responsible for designing, implementing, testing, documenting, packaging, and delivering Stoá as a production-quality cybersecurity platform.

Treat this document as the authoritative project specification. Do not silently remove requirements, replace difficult features with mock implementations, or claim unfinished functionality is complete.

## 1. Product vision

Stoá is a modular cybersecurity platform for Windows and Linux. It combines network scanning, traffic analysis, intrusion detection, authorized web security testing, file monitoring, phishing detection, password auditing, firewall simulation, and encrypted team communication in one secure workspace for IT teams.

This is an authorized defensive-security product. It must not provide unrestricted offensive functionality or encourage testing systems without permission.

The product must provide:

- A polished PySide6 desktop application for Windows and Linux
- A self-hosted central server
- Team accounts and role-based access
- Endpoint enrollment and management
- Configurable security modules
- Real-time alerts and job progress
- Explainable findings and remediation guidance
- Searchable audit history
- Report export
- Secure local handling of sensitive evidence
- Reproducible builds and straightforward installation

## 2. Required modules

### 2.1 Port and service scanner

Implement:

- TCP connect scanning
- Optional authorized SYN scanning with Scapy
- Configurable single ports, ranges, and approved presets
- IPv4 support initially, with interfaces prepared for later IPv6 support
- Host reachability checks
- Port state classification
- Safe banner collection
- Service identification
- Scan cancellation
- Per-host concurrency controls
- Connection timeouts
- Rate limiting
- Progress reporting
- Structured results
- JSON and human-readable reports

Do not include stealth, evasion, source-spoofing, or denial-of-service features.

### 2.2 Packet sniffer

Implement:

- Network-interface selection
- Protocol filtering
- Packet metadata inspection
- TCP, UDP, ICMP, ARP, DNS, HTTP-metadata, and TLS-metadata views
- Search and filtering
- Packet-count and bandwidth summaries
- Rotating local PCAP capture
- Export for Wireshark validation
- Configurable retention limits
- Suspicious-pattern indicators
- Capture cancellation and clean shutdown

Raw packet payloads and PCAP files must remain local unless a user explicitly exports them.

### 2.3 Authorized web security scanner

Implement:

- Same-origin crawling
- URL, link, form, input, cookie, header, and parameter discovery
- Configurable crawl depth and page limits
- Passive security-header checks
- Cookie security checks
- TLS and redirect observations
- Rate-limited SQL-injection indicators
- Rate-limited reflected and stored-XSS indicators
- Authentication/session observations based only on measurable behavior
- Optional OWASP ZAP integration
- Evidence redaction
- Clear confidence levels
- Remediation guidance

Only scan explicitly allowlisted targets covered by a valid authorization record. Do not claim to detect all broken authentication automatically. Report specific observable weaknesses instead.

### 2.4 Firewall simulator

Implement an explainable rule simulator supporting:

- Source and destination IP addresses
- CIDR ranges
- Source and destination ports
- TCP, UDP, ICMP, and any-protocol matching
- Inbound and outbound direction
- Ordered rules
- Allow and block actions
- First-match evaluation
- Default policy
- Rule validation
- Shadowed-rule detection
- Conflicting-rule detection
- Test-packet generation
- Replay from captured packet metadata
- Visual explanations showing which rule matched and why
- Policy import and export

This module must simulate decisions only. It must not modify Windows Firewall, nftables, iptables, or other host firewall settings in the initial release.

### 2.5 Offline password-auditing lab

Implement:

- Local-only hash input
- Hash-format detection for explicitly supported formats
- Dictionary auditing
- Bounded brute-force demonstrations
- Rule-based candidate generation
- Educational precomputed-table demonstrations
- Configurable attempt and time limits
- Progress and cancellation
- Password-strength findings
- Remediation recommendations

Never capture live passwords, intercept credentials, attack online login services, or upload hashes and wordlists to the central server. Clearly distinguish educational demonstrations from realistic auditing of modern password hashes.

### 2.6 Keylogger detector

Use Windows- and Linux-specific adapters to inspect:

- Running processes
- Process ancestry
- Executable location
- File hashes
- Digital-signature or package-trust information where available
- Startup persistence
- Suspicious keyboard-hook or input-device access indicators
- Unexpected background listeners
- Known benign accessibility and input tools
- Risk factors and confidence scoring

This is heuristic detection. Never present an indicator as definitive malware proof. Provide evidence and explain possible false positives.

### 2.7 Phishing-page detector

Analyze:

- URL structure
- Domain and subdomain characteristics
- Redirect chains
- TLS certificate facts
- Domain-age information when legally and technically available
- Lookalike-domain indicators
- Form destinations
- Password fields
- External-resource ratios
- Page-title and brand inconsistencies
- Suspicious text patterns
- Obfuscated links
- IP-address URLs
- Punycode and Unicode lookalikes

Use a versioned scikit-learn pipeline for risk scoring. Keep heuristic explanations visible even when a machine-learning model is used. Store training-data provenance, model version, evaluation metrics, thresholds, and known limitations.

Do not automatically submit forms or credentials.

### 2.8 Intrusion detection system

Implement real-time and replay-based detection for:

- Port-scan patterns
- Repeated connection failures
- Repeated authentication-failure metadata
- Traffic spikes
- Unusual protocol distribution
- Suspicious DNS behavior
- ARP anomalies
- Configurable signatures
- Configurable thresholds and rolling windows
- Alert suppression and deduplication
- Severity and confidence
- Investigation timelines

Use packet metadata rather than centrally storing raw payloads.

### 2.9 File integrity monitor

Implement:

- Directory selection
- Recursive and non-recursive monitoring
- Initial hash baselines
- Create, change, delete, and rename events
- SHA-256 hashing
- Large-file handling
- Debouncing of rapid changes
- Include and exclude patterns
- Permission-error reporting
- Baseline approval and renewal
- Tamper-evident event records
- Real-time alerts
- Exportable change history

Protect Stoá’s own configuration, audit data, and baseline files from silent modification.

### 2.10 End-to-end encrypted chat

Implement this as an isolated subsystem with:

- Per-device identity keys
- Authenticated key establishment
- Device verification
- AES-GCM or another audited authenticated-encryption primitive
- Unique nonces
- Message authentication
- Replay protection
- Key rotation
- Offline delivery
- Ciphertext-only server relay
- Local encrypted message storage
- Explicit device revocation
- Clear verification state in the UI

Use established, maintained cryptographic libraries and documented protocols. Do not invent cryptographic algorithms or casually combine RSA and AES. Private keys must never leave the device unencrypted.

Treat a professional cryptographic review as required before claiming production readiness.

## 3. Architecture

Use a Python monorepo with clearly separated packages for:

- Desktop application
- Central API
- Background workers
- Shared schemas and domain models
- Security modules
- Platform-specific adapters
- Database migrations
- Packaging
- Documentation
- Tests
- Safe lab fixtures

Primary technology choices:

- Python
- PySide6
- FastAPI
- Pydantic
- PostgreSQL
- SQLAlchemy
- Alembic
- WebSockets
- Scapy
- psutil
- watchdog
- Requests or HTTPX
- BeautifulSoup
- scikit-learn
- Optional OWASP ZAP integration
- Docker and Docker Compose
- pytest
- Ruff
- mypy or Pyright
- Bandit
- pip-audit
- Node.js/npm as the root command interface

Prefer maintained libraries over custom infrastructure.

### Desktop agent

The desktop application must:

- Run primarily without administrator/root privileges
- Use a narrowly scoped privileged helper only when required
- Display permission requirements before privileged operations
- Provide navigation for Dashboard, Endpoints, Jobs, Findings, Alerts, Modules, Chat, Reports, Policies, Audit Log, and Settings
- Support responsive long-running operations without freezing the UI
- Restore safe state after crashes
- Queue server events during temporary disconnections
- Clearly show whether data is local or centrally synchronized

### Central server

The server must provide:

- Team and user management
- Endpoint enrollment
- Authentication
- Role-based authorization
- Module policies
- Authorization scopes
- Job coordination
- Finding and alert storage
- Audit logging
- Report metadata
- WebSocket updates
- Health and readiness endpoints
- Database migrations
- Backup and restore documentation

### Shared entities

Define and document at least:

- `User`
- `Team`
- `Role`
- `Endpoint`
- `Asset`
- `AuthorizationScope`
- `ModulePolicy`
- `Job`
- `JobProgress`
- `Finding`
- `Alert`
- `EvidenceReference`
- `Report`
- `AuditEvent`
- `ChatDevice`
- `EncryptedEnvelope`

Use versioned APIs and schemas. Validate all untrusted input.

## 4. Roles and permissions

Support these roles:

### Administrator

- Manage team members
- Enroll or revoke endpoints
- Create authorization scopes
- Configure policies
- View audit events
- Manage retention settings
- Run approved jobs

### Analyst

- Run jobs within approved scopes
- Investigate findings and alerts
- Add investigation notes
- Generate reports
- Use encrypted chat

### Viewer

- View authorized dashboards, findings, alerts, and reports
- Cannot run scans or change policies

Enforce permissions on the server and agent. Hiding a UI button is not sufficient authorization.

## 5. Authorization and safety controls

Every active security job must include:

- Module identifier
- Requesting user
- Executing endpoint
- Explicit target
- Matching allowlist entry
- Authorization owner
- Business justification
- Valid-from timestamp
- Expiration timestamp
- Rate policy
- Module configuration
- Audit correlation identifier

Reject jobs when:

- Authorization is missing
- Authorization is expired
- The target is outside scope
- The user lacks permission
- The endpoint is not approved
- Rate limits are invalid
- Required local permissions are missing
- Configuration validation fails

Default active scanning to loopback, private lab networks, and supplied safe fixtures until an administrator creates an explicit scope.

Do not add:

- Exploit delivery
- Persistence
- Credential theft
- Payload generation
- Evasion
- Stealth scanning
- Destructive testing
- Denial-of-service behavior
- Unauthorized remote command execution

## 6. Data classification and storage

Store centrally by default:

- Users and teams
- Enrolled endpoint metadata
- Policies
- Authorization scopes
- Job metadata
- Redacted findings
- Alerts
- Audit events
- Report metadata

Keep local by default:

- Raw PCAP files
- Packet payloads
- Password hashes
- Wordlists
- Sensitive web evidence
- Local filesystem evidence
- Chat private keys
- Decrypted chat content

Implement:

- Encryption in transit
- Secure secret storage
- Log redaction
- Configurable retention
- Secure deletion where feasible
- Database backups
- Restore validation
- Audit trails
- Data export
- Privacy documentation

Never store credentials, tokens, private keys, or secrets in logs or source control.

## 7. Installation and build experience

The project must be easy for non-technical users to install and run.

Provide a root-level npm command interface:

```text
npm install
npm run setup
npm run dev
npm run build
npm run install-app
npm start
npm test
npm run lint
npm run typecheck
npm run security
npm run server:up
npm run server:down
```

Requirements:

- Keep Python as the application language.
- Use Node/npm only as a consistent command, setup, build, and packaging interface.
- Automatically create and manage the Python virtual environment.
- Automatically install pinned Python dependencies.
- Pin supported Python and Node.js versions.
- Commit appropriate lockfiles.
- Detect unsupported platforms and missing prerequisites.
- Produce actionable error messages.
- Do not require users to run manual `pip` commands.
- Do not require administrator/root access for the entire application.
- Request elevation only for narrowly scoped operations.
- Provide safe Windows PowerShell and Linux shell setup scripts behind npm commands.
- Include an `.env.example` containing no real secrets.
- Add a first-run setup wizard.
- Support clean upgrades without losing configuration, evidence, encryption keys, or database state.
- Require explicit confirmation before deleting user data during uninstall.

Create production artifacts:

- Signed Windows installer or portable executable
- Linux AppImage or equivalent self-contained package
- Versioned Docker images
- Docker Compose deployment
- Checksums for release artifacts
- Release notes
- Software bill of materials where practical

End users installing packaged releases must not need Node.js, npm, Python, source code, or development tools.

Document:

- Development setup
- Production build
- Desktop installation
- Server deployment
- Upgrade
- Rollback
- Repair
- Backup
- Restore
- Uninstall
- Packet-capture permissions
- Npcap requirements on Windows
- Linux capture capabilities
- Troubleshooting

`npm run build` must fail if required tests, linting, type checks, security checks, or packaging validations fail.

## 8. User experience

Provide:

- A professional dark and light theme
- Accessible color contrast
- Keyboard navigation
- Loading, empty, error, offline, and permission-denied states
- Confirmation for dangerous or irreversible operations
- Clear progress and cancellation controls
- Explainable findings
- Search, filtering, sorting, and pagination
- Notification preferences
- Local-versus-central data labels
- First-run onboarding
- Safe default settings
- Exportable reports
- No placeholder controls in production screens

Avoid presenting every module as an unrelated tool. Use a shared workflow:

1. Select or register an asset
2. Confirm authorization
3. Configure a module
4. Run or schedule a job
5. Observe progress
6. Review findings
7. Investigate evidence
8. Apply remediation
9. Export a report
10. Preserve the audit record

## 9. Testing and quality requirements

Implement:

- Unit tests
- Integration tests
- API tests
- Database migration tests
- Permission tests
- Authorization-boundary tests
- UI tests for critical workflows
- Windows platform tests
- Linux platform tests
- Packaging smoke tests
- Upgrade and rollback tests
- Offline and reconnection tests
- Cancellation and timeout tests
- Security regression tests
- Malformed-input tests
- Concurrency tests where applicable

Use isolated fixtures and lab services for:

- Known open and closed ports
- Service banners
- Deterministic PCAP replay
- Port-scan detection
- Authentication-failure events
- Traffic spikes
- Intentionally vulnerable web behavior
- Safe SQL-injection and XSS indicators
- File create/change/delete/rename events
- Benign and suspicious process indicators
- Phishing and legitimate-page samples
- Password-auditing examples
- Chat tampering, replay, revocation, rotation, and offline delivery

Never run tests against public systems without explicit authorization.

Quality gates:

- Tests pass
- Formatting passes
- Linting passes
- Type checking passes
- Dependency auditing passes
- Static security checks pass
- Build succeeds
- Installation smoke test succeeds
- No committed secrets
- No unexplained high-severity dependency vulnerabilities
- Documentation matches actual behavior

## 10. GitHub ownership and identity

All repository work must target the GitHub account:

```text
Flotrpy
```

Use this repository-local commit email:

```text
affanshaik2009@gmail.com
```

Requirements:

- Configure Git identity for this repository only, not globally.
- Confirm the authenticated GitHub account is `Flotrpy`.
- Confirm the remote repository belongs to `Flotrpy`.
- Do not push to a repository owned by another account.
- Do not expose GitHub tokens or credentials.
- If GitHub email privacy prevents using the supplied address, use the account’s verified no-reply address and document the substitution.
- Use branch names prefixed with `codex/`.
- Protect the default branch.
- Never force-push shared branches.
- Never discard existing user changes.
- Attach every created pull request to the Codex task.

## 11. Commit and pull-request requirements

Deliver the project through exactly 10 meaningful pull requests.

The project target is at least 100 meaningful commits across those pull requests.

A meaningful commit must:

- Represent one coherent, reviewable change
- Leave the branch in a valid state
- Use a descriptive Conventional Commit message
- Include related tests when appropriate
- Avoid mixing unrelated concerns

Do not count these toward the target:

- Empty commits
- Merge commits
- Formatting-only commits
- Typo-only commits
- Generated files by themselves
- Lockfile changes without a related dependency decision
- Artificially split changes
- Reverts created merely to increase the count

Do not manufacture low-quality history to reach 100 commits. If the implementation cannot justify 100 genuinely useful commits, report the discrepancy rather than corrupting the repository history.

Maintain a version-controlled ledger containing:

- Commit number
- Commit hash
- Commit subject
- Pull request number
- Requirement addressed
- Tests executed
- Result
- Remaining work

Every pull request must include:

- Summary
- Requirements addressed
- Architecture notes
- Security considerations
- Screenshots for UI work
- Test evidence
- Installation impact
- Migration impact
- Risks
- Known limitations
- Review checklist
- Rollback instructions

Each pull request must be independently reviewable and leave the project runnable.

## 12. Required pull-request sequence

### PR 1 — Foundation

Create:

- Monorepo structure
- Root npm command wrapper
- Python dependency management
- Formatting, linting, typing, and test configuration
- CI foundation
- Docker Compose development foundation
- Architecture documentation
- Threat-model outline
- Contribution guide
- Decision log
- Commit/PR ledger
- Initial desktop and server shells

### PR 2 — Identity and shared platform

Implement:

- Shared schemas
- PostgreSQL models
- Migrations
- Authentication
- Teams
- Roles
- RBAC
- Endpoint records
- Authorization scopes
- Audit events
- Health checks
- API versioning

### PR 3 — Desktop foundation

Implement:

- PySide6 application shell
- Navigation
- First-run wizard
- Endpoint enrollment
- Secure local storage
- API client
- WebSocket client
- Background jobs
- Offline queue
- Connectivity states
- Settings
- Theme support

### PR 4 — Port scanner

Implement the complete authorized port and service scanner, UI, API integration, reports, tests, and safe lab fixtures.

### PR 5 — Packet analysis and IDS

Implement packet capture, protocol views, local PCAP management, deterministic replay, IDS detection, alerting, Wireshark validation, UI, and tests.

### PR 6 — Web security scanner

Implement same-origin crawling, passive checks, authorized active probes, evidence handling, optional OWASP ZAP integration, UI, reports, and tests.

### PR 7 — Firewall simulator

Implement the rule engine, validation, conflict analysis, packet simulation, replay, explainable visualization, policy import/export, and tests.

### PR 8 — Endpoint monitoring

Implement file integrity monitoring and Windows/Linux keylogger-detection adapters, including baselines, alerts, UI, and tests.

### PR 9 — Risk-analysis tools

Implement phishing detection and the constrained offline password-auditing lab, including model documentation, local-only sensitive data, UI, reports, and tests.

### PR 10 — Secure chat and release hardening

Implement encrypted chat, full integration, native installers, release packaging, clean-environment verification, backup/restore, upgrade/rollback, operational documentation, security review, and release readiness.

## 13. Execution process

Do not attempt the whole project as one uncontrolled change.

First:

1. Inspect the repository.
2. Preserve existing work.
3. Confirm the current branch and Git status.
4. Confirm GitHub authentication and repository ownership.
5. Configure repository-local Git identity.
6. Review this specification for contradictions or unsafe requirements.
7. Create:
   - `SPEC.md`
   - `PLAN.md`
   - `STATUS.md`
   - `DECISIONS.md`
   - `SECURITY.md`
   - `THREAT_MODEL.md`
   - `docs/development-ledger.md`
8. Map every requirement to a pull request and acceptance test.
9. Identify prerequisites and risks.
10. Begin PR 1 only.

For each pull request:

1. Create a `codex/` branch.
2. Break the work into coherent tasks.
3. Implement one coherent change at a time.
4. Add or update tests with the change.
5. Run focused tests.
6. Commit only after verification.
7. Update status and decision documentation.
8. Run the complete applicable quality suite.
9. Review the final diff.
10. Scan for secrets.
11. Push the branch.
12. Create the pull request.
13. Attach the pull request to this Codex task.
14. Wait for review or explicit authorization before merging or beginning work that depends on unmerged changes.

Do not create empty commits, fake test results, fabricated screenshots, placeholder implementations presented as complete, or misleading pull-request descriptions.

## 14. Definition of done

Stoá is complete only when:

- All ten modules are implemented within the stated safety boundaries.
- All ten meaningful pull requests have been completed.
- The commit ledger contains at least 100 genuinely meaningful commits, or clearly reports why that target could not be met responsibly.
- Windows and Linux builds succeed.
- Clean installation tests succeed.
- The central server deploys through Docker Compose.
- Database migrations work from a clean database and through supported upgrades.
- Required tests and quality gates pass.
- Active operations cannot bypass authorization controls.
- Sensitive local-only data is not uploaded centrally.
- Encrypted chat keys remain device-controlled.
- Reports and findings are explainable.
- Documentation matches actual behavior.
- Backup, restore, upgrade, rollback, repair, and uninstall procedures are verified.
- No secrets are committed.
- Known limitations are documented.
- The project can be installed by an end user without manually configuring Python.
- A new developer can clone the repository, run the documented npm setup commands, and start a development environment successfully.

## 15. Immediate instruction

Start by inspecting the repository and reporting:

- Current files
- Git status
- Current branch
- Configured remotes
- Authenticated GitHub account
- Available development tools
- Missing prerequisites
- Major delivery risks
- Proposed PR 1 task breakdown
- Proposed meaningful commits for PR 1
- PR 1 acceptance criteria

Do not implement later pull requests yet. After the inspection and plan are clear, execute PR 1 completely, verify it, and prepare it for review.
