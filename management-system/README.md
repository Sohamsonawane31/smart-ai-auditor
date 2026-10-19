# Audit Management System

This documentation-only component describes the optional Streamlit layer that
uses the existing Smart AI Auditor engine; it is not a second application.

Start it with the primary project's environment:

```powershell
cd D:\Auditor\Smart_project_auditor
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-management.txt
python -m streamlit run audit_management.py
```

Register a project with either an existing local directory or a public GitHub
URL. URLs are cloned safely into an isolated temporary directory; they are
never treated as local paths. On **Run audit**, choose the project, confirm the
target, select a supported provider and formats, then start the run. Each run
has its own ID and output directory. JSON is always generated in addition to
the selected formats because it is required for automatic finding import.

Successful runs register the JSON report once, create finding snapshots, and
appear immediately in Reports, Findings & actions, Dashboard, and History.
Reviewers can validate or reject findings and create/update corrective actions.
Manual import is separate and requires a selected compatible JSON file.

Data is local: `management_data/audit_management.json`; generated artifacts
are in `management_data/audit_runs/<project-id>/<run-id>/`. Back up both while
the UI is stopped, and restore by copying them back as a matched set. Do not
merge store JSON manually.

Only a confirmed-dead local run is automatically marked **Interrupted** after
restart. Unverifiable Running records stay protected until an operator marks
them interrupted with a reason. Failed/interrupted runs can be retried; retry
always creates a new run ID and output directory. Failed, incomplete, or
provider-failed runs are never imported as successful results.

This is a local single-user pilot tool. Authentication, roles, shared durable
workers, private Git credentials, and resumable execution are intentionally
out of scope.
