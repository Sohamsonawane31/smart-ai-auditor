# Architecture

The CLI and Streamlit UI share `ai_project_auditor.core.engine.AuditEngine`.
The UI adds local workflow and persistence; it does not duplicate audit rules.

```text
audit.py -------------------------------> AuditEngine -> reports
audit_management.py -> AuditManagementService -> AuditEngine -> JSON import
                                                -> reports/findings/actions/history
```

The engine analyzes a local directory or an isolated clone of a supported public
GitHub repository. Its scanner pipeline creates a normalized report, from which
JSON, Markdown, Excel, and PDF generators render consistently. The management
service associates a generated/imported JSON report and immutable findings with
a registered project. Human decisions and corrective actions remain separate
from scanner evidence.
