# Security policy

## Authorized use

Stoá is intended only for systems covered by explicit, current authorization. Do not use this project to scan, monitor, or test third-party systems without permission.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private GitHub security advisory to the repository owner with affected versions, reproduction conditions, impact, and any suggested mitigation. Do not include live credentials, private packet captures, or customer evidence.

## Supported versions

No production version has been released. Security fixes currently target the active development branch.

## Engineering rules

- Never commit credentials, tokens, private keys, production evidence, hashes, wordlists, or packet captures.
- Use the central authorization service for every active operation; UI visibility is not authorization.
- Bind development services to loopback unless an explicit deployment configuration says otherwise.
- Redact sensitive values before logging and before central synchronization.
- Use maintained cryptographic libraries and established protocols; no bespoke cryptography.
- Keep privileged helpers narrow, explicit, and separately auditable.
- Treat dependency-audit failures as release blockers until assessed and documented.

Run `npm run security` before submitting a change.

