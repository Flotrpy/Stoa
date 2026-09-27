# Identity and authorization

PR 2 establishes the server-side trust boundary used by every later security module.

## Bootstrap and authentication

`POST /api/v1/auth/bootstrap` works only while the user table is empty. It creates one team, one administrator, the fixed role catalog, and the first audit event in a single transaction. Subsequent calls return a conflict.

Passwords are hashed with pwdlib's maintained Argon2 recommendation. Successful login returns a short-lived HS256 access token bound to one user and one team. The signing secret must be unique and at least 32 characters in production. The server loads the current user, team membership, and role from the database on every authorized request, so disabled users and removed memberships do not remain authorized for the token's full lifetime.

## Permission matrix

| Capability | Administrator | Analyst | Viewer |
| --- | :---: | :---: | :---: |
| Manage members | Yes | No | No |
| Register, approve, or revoke endpoints | Yes | No | No |
| Create authorization scopes | Yes | No | No |
| Configure module policies | Yes | No | No |
| View audit events | Yes | No | No |
| Queue authorized jobs | Yes | Yes | No |
| Investigate findings and generate reports | Yes | Yes | No |
| Use encrypted chat | Yes | Yes | No |
| View team-scoped records | Yes | Yes | Yes |

The API returns 404 for a mismatched team identifier where revealing another team's existence would be unnecessary. Permission checks are server dependencies; desktop controls are never the authorization boundary.

## Active-job gate

Job creation fails closed unless all of these are true:

- the requester has the `run_jobs` permission;
- the executing endpoint belongs to the same team and is approved;
- the authorization scope belongs to the team and is active;
- the current time is inside the scope's validity window;
- the requested module is listed in the scope;
- the exact target matches an explicit host, CIDR, or same-origin URL path prefix;
- the scope contains a bounded rate policy;
- the team module policy exists and is enabled; and
- the request schema, justification, and module configuration are valid.

Accepted jobs copy the approved rate policy and receive an audit correlation identifier. Rejections are also audited without storing credentials or sensitive evidence. Wildcard scope matching is intentionally unsupported in this phase.

## Audit integrity

Audit events are append-oriented and contain the previous event digest. The digest covers the team, actor, action, resource, correlation identifier, redacted event data, predecessor hash, and timestamp. This makes offline deletion or modification detectable. Database authorization and backup controls remain necessary; a hash chain is not a substitute for protected storage.

## Data ownership

Every central operational entity carries a team identifier or inherits one through a constrained parent. API queries always include the current team. Raw packet payloads, password material, private keys, decrypted chat, and sensitive local evidence are not represented as centrally uploadable fields.
