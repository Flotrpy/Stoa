# Architecture

Stoá is a Python monorepo exposed through a consistent npm operator interface.

```text
PySide6 desktop ── authenticated HTTPS/WebSocket ── FastAPI control plane
       │                                                │
       ├── local encrypted configuration                ├── PostgreSQL metadata
       ├── local evidence store                         ├── job coordination
       ├── platform adapters                            └── redacted findings/audit
       └── bounded security workers
```

Package responsibilities:

- `stoa_desktop`: human workflows, local/central state presentation, permission prompts, and cancellation.
- `stoa_server`: versioned API, authentication/authorization, policy and job coordination, centrally permitted metadata.
- `stoa_shared`: strict versioned schemas and settings shared across process boundaries.
- `stoa_workers`: cancellable job execution and progress contracts.
- `stoa_security`: bounded module interfaces and authorization inputs.
- `stoa_platform`: Windows/Linux adapters isolated from domain logic.

The control plane coordinates; it does not become a warehouse for sensitive endpoint evidence. Security modules execute close to the authorized asset, produce explainable structured results, and reference local evidence through opaque identifiers. Persistent domain entities and migrations arrive in PR 2 after their policy boundaries are reviewable.
