# Desktop foundation

PR 3 turns the PySide6 shell into a functional, unprivileged central-service client without implementing security-module screens early.

## State and storage

- Non-secret settings live in the per-user platform configuration directory and are replaced atomically.
- Short-lived access tokens live in the operating-system credential vault through `keyring`; passwords are never persisted.
- The SQLite offline queue stores only an allowlisted class of operational metadata. Recursive client checks reject sensitive field names, and the server independently enforces a bounded flat schema.
- Endpoint and team UUIDs are identifiers, not credentials. A registered endpoint remains pending until an administrator approves it centrally.

## Connectivity lifecycle

1. Startup renders local state immediately and restores credentials in a Qt thread-pool task.
2. Health and principal checks produce explicit local-only, online, offline, or authentication-required states.
3. First-run connection exchanges credentials for a short-lived token, persists the token in the OS vault, and discards the password.
4. The authenticated WebSocket stream is team-bound and reconnects with bounded exponential delay.
5. On reconnection, safe queued events are acknowledged only after a `202 Accepted` response. Synchronization stops at the first failure to preserve ordering.

The desktop does not require administrator privileges. Later packet-capture and endpoint-protection features must use narrowly scoped adapters rather than elevating the full application.

## User experience boundary

Dashboard and Settings are functional in this delivery. Navigation for modules scheduled in PRs 4–10 remains disabled and labeled as unavailable, preventing placeholder controls from being mistaken for working security capabilities. The only themes are deliberate light and dark modes. Broader visual research and refinement occurs after backend workflows are stable, as recorded in ADR-005.
