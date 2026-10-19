# Smart AI Auditor

Smart AI Auditor is a static-first software-audit tool with an optional local
management layer. It helps developers, auditors, and small delivery teams
inspect repositories, produce consistent evidence-based reports, track review
decisions, and follow corrective actions through to closure.

The project has two entry points that share one authoritative engine:

- `audit.py` is the command-line tool for running audits and generating reports.
- `audit_management.py` is the optional Streamlit UI for project registration,
  managed runs, report import, findings review, corrective actions, and history.

It is intended for local development and controlled single-user pilots. It is
not a hosted multi-user or production compliance platform.

## Architecture

```text
Project registration / CLI target
        -> local-path or public-GitHub validation
        -> shared AuditEngine
        -> inventory, technology detection, checklist and scanners
        -> optional NVIDIA NIM or OpenCode Zen reasoning
        -> JSON / Markdown / Excel / PDF reports
        -> management JSON report registration
        -> findings, corrective actions, audit history
```

The management UI always requests JSON for a managed run because JSON is the
import contract; any selected Markdown, Excel, and PDF reports are generated
alongside it. See [architecture](docs/architecture.md).

## Features

- Offline deterministic auditing without an API key or network connection.
- Public GitHub targets cloned into an isolated temporary workspace.
- Static security, dependency, code-quality, test, API, DevOps, and AI-focused
  scanners, with an Excel checklist and applicability filtering.
- Optional, bounded and redacted LLM reasoning through NVIDIA NIM or OpenCode
  Zen; malformed or failed provider responses are not represented as success.
- JSON, Markdown, Excel, and PDF reports generated from one normalized report.
- Optional local management of projects, run status/recovery, report imports,
  immutable finding snapshots, manual assessments, and corrective actions.

## Requirements and installation (Windows)

Python 3.10 or newer is required. The current environment has been verified on
Python 3.14.6 with the declared dependencies. Git is required only for public
GitHub targets. Create a virtual environment if `.venv` does not yet exist:

```powershell
cd D:\Auditor\Smart_project_auditor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-management.txt
```

`requirements.txt` is sufficient for the CLI. `requirements-management.txt`
adds Streamlit for the optional management UI.

## Run the management UI

```powershell
cd D:\Auditor\Smart_project_auditor
.\.venv\Scripts\Activate.ps1
python -m streamlit run audit_management.py
```

Streamlit normally opens `http://localhost:8501`. If it does not, copy the URL
printed in the terminal. If `streamlit` cannot be found, use the command above
from the activated primary-project virtual environment and reinstall
`requirements-management.txt`.

## Run the CLI

```powershell
python audit.py --help
python audit.py --repo "D:\Path\To\Project" --provider offline --format all
python audit.py --github "https://github.com/owner/repository" --provider offline --format json,markdown
```

Supported providers are `offline`, `nvidia`, and `opencode`. Supported formats
are `json`, `markdown`, `excel`, `pdf`, and `all`.

## Provider configuration

Copy `.env.example` to `.env`; never commit `.env`.

```text
NVIDIA_API_KEY=...
OPENCODE_API_KEY=...
```

- **offline** performs only deterministic analysis and sends no source to an
  external LLM.
- **nvidia** uses NVIDIA NIM's OpenAI-compatible chat-completions endpoint;
  its default model is `meta/llama-3.3-70b-instruct`.
- **opencode** uses OpenCode Zen's compatible chat-completions endpoint; its
  default model is `kimi-k2.7-code`.

Only redacted, bounded audit context is sent to a selected provider. Obtain
client authorization before using external providers. Missing credentials,
authentication failures, rate limits, timeouts, network failures, and malformed
responses are surfaced. In the management UI they mark the run **Failed** and
prevent report import; they never silently become an offline success.

## Management workflow

1. Register a project in **Projects** with an existing local repository or a
   valid public GitHub URL.
2. In **Run audit**, confirm the project target, choose a provider and formats,
   then start the background managed run.
3. Review registered artifacts in **Reports** and immutable finding snapshots
   in **Findings & actions**.
4. Validate or reject findings, create corrective actions, and update their
   status.
5. Review assessments, reports, runs, and actions in **History**.

Each managed run has a distinct ID and output directory. A confirmed-dead local
process is recovered as **Interrupted** after restart; uncertain runs stay
locked until an operator explicitly confirms they stopped. Retries use new IDs
and never overwrite the original run.

## Reports, data, and backup

CLI reports default to `reports/` unless `--output` is supplied. Managed
artifacts are stored under:

```text
management_data/
  audit_management.json
  audit_runs/<project-id>/<run-id>/
```

These locations contain local/private audit evidence and are intentionally
ignored by Git. To back up management data, stop the UI and copy both the store
file and required run directories to secure storage. Restore them as a matched
set; do not manually merge JSON files. Retain or delete local reports according
to the client engagement's retention policy.

## Testing

```powershell
python -m pytest tests -q
python audit.py --help
python -m pip check
```

The suite covers CLI behavior, scanners, provider HTTP contracts (mocked),
reports, management persistence, recovery, duplicate prevention, and an actual
disposable local managed offline audit. Live NVIDIA/OpenCode tests require
authorized credentials and are not run automatically.

## Security and limitations

- The application does not execute audited project code.
- Findings are review input, not a guarantee of compliance or absence of risk.
- The management layer is local and single-user: no authentication, roles,
  durable distributed workers, private Git authentication, or multi-user
  concurrency model is provided.
- External LLM availability and provider policy are outside this project's
  control.

Read the focused guides for the [audit engine](ai_project_auditor/README.md),
[management service](ai_project_auditor/management/README.md), and publishing
and operational details in [troubleshooting](docs/troubleshooting.md) and
[security](docs/security.md).

## License

Licensed under the [MIT License](LICENSE).
