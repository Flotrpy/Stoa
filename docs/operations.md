# Operations and release runbook

## Release

Run `npm run build` from a clean checkout, then `npm run release`. The release task repeats the
quality gate, creates a native single-file desktop executable with PyInstaller, emits an SPDX 2.3
SBOM, and writes SHA-256 checksums. Windows Authenticode and Linux package signing require
organization-controlled signing credentials and must run in the protected release environment;
unsigned local artifacts must not be represented as production releases.

End users of the portable artifact do not need Node.js, npm, Python, source code, or compilers.
Validate the artifact on clean supported Windows and Linux machines before publication. Preserve
the SBOM, checksums, CI run, installer smoke results, release notes, and signing evidence together.

## Upgrade, repair, rollback, and uninstall

Before upgrade, create and verify a database backup, preserve the prior signed artifact, apply
Alembic migrations, and run readiness checks. Repair reinstalls the same signed version without
modifying the database. Rollback requires restoring the matching database backup before launching
the prior binary when a migration is not backward compatible. Uninstall removes application files
only; deleting local evidence, chat keys, configuration, or databases is a separate explicit step.

## Backup and restore

SQLite development deployments use `python scripts/release.py backup SOURCE DESTINATION` and
`restore BACKUP DESTINATION`. Both paths run SQLite integrity checks and restore through an atomic
replacement. PostgreSQL production deployments must use `pg_dump --format=custom` and
`pg_restore` under a least-privileged database operator account, with encryption at rest and a
documented restore drill. Never include decrypted chats, password-lab inputs, or endpoint-private
keys in central backups.

## Incident response

Revoke affected endpoints and chat devices, rotate credentials and device keys, retain immutable
audit/export evidence, and investigate correlated job and alert identifiers. Do not renew a file
baseline or delete an alert until the underlying change has been validated.
