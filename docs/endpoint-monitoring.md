# Endpoint monitoring

PR 8 adds local file-integrity baselines and explainable Windows/Linux process indicators.

## File integrity

- Baselines record relative path, size, modification time, and SHA-256 for files within an
  explicitly selected directory. Directory symlinks are not followed.
- Recursive traversal, include/exclude patterns, large-file hash limits, permission errors,
  create/change/delete/rename classification, and approved baseline renewal are supported.
- Every emitted event includes a hash chained to the prior event and baseline identifier.
  `verify_event_chain` detects altered or reordered history.
- Baseline manifests remain on the endpoint. Central storage receives bounded change metadata,
  chain hashes, findings, alerts, and reports, not file contents.

## Input-monitoring indicators

The Windows and Linux adapters inspect supplied process metadata for combinations of input API
or device references, suspicious execution locations, persistence paths, and Windows signature
state. A single weak signal is not reported. Results include confidence and an explicit statement
that the indicator is triage evidence, not proof.

Stoá never hooks keyboard APIs, reads input devices, captures keystrokes, or uploads command
output containing sensitive input. Platform collection requiring elevated access is intentionally
outside this adapter.

## Operational boundary

Monitoring requires endpoint enrollment, an active authorization scope, and an enabled central
module policy. File-size and process-inspection controls are enforced centrally. Medium/high
observations create deduplicated alerts. Baselines should be renewed only after an operator has
validated the recorded changes.
