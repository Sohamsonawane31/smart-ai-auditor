# Audit Management service

`management.service.AuditManagementService` is the local persistence and
workflow boundary used by `audit_management.py`. It does not contain a second
auditor: managed runs instantiate the package's existing `AuditEngine`.

## Responsibilities

- Register projects with either a local directory or a public GitHub URL.
- Validate local paths and normalize supported GitHub URLs without treating a
  URL as a Windows path.
- Run a selected project in the background, with a per-project lock, unique run
  ID, and unique output directory.
- Import only a valid generated JSON report once; retain immutable finding
  snapshots and separate reviewer decisions.
- Store manual assessments, corrective actions/statuses, reports, run history,
  and recovery state in atomic local JSON storage.

## Run lifecycle

Runs progress through `Running`, `Completed`, `Failed`, or `Interrupted`.
JSON is added to managed output even if a user only selects another report
format because it is required for safe import. Failed, malformed, incomplete,
or provider-failed runs are not imported. A retry creates new identifiers and
does not overwrite historical artifacts.

On application startup, a Running record is automatically interrupted only
when its recorded local process is confirmed dead. A live or unverifiable
process remains protected until an operator confirms it stopped and supplies a
reason. This conservative policy prevents accidental duplicate audits.

## Storage and operations

The default local store is `management_data/audit_management.json`; run
artifacts are in `management_data/audit_runs/`. Stop the UI before backing up
or restoring these paths. They are private local data and must not be committed.

Start the UI from the repository root with:

```powershell
python -m streamlit run audit_management.py
```

Common problems: use a readable JSON file—not a directory—for manual imports;
configure an existing local directory or public GitHub URL; set the appropriate
provider key in `.env`, or choose offline mode. Authentication, roles,
multi-user hosting, private Git credentials, and resumable durable workers are
not implemented.

See the root [product guide](../../README.md) and the
[engine guide](../README.md).
