# Smart AI Auditor engine

This directory is documentation-only. The engine remains in the repository root
(`audit.py` and `ai_project_auditor/`) so existing imports and CLI behaviour do
not change.

The auditor statically inventories a local repository, detects technologies,
filters the Excel checklist, runs deterministic scanners, verifies findings,
and creates JSON, Markdown, Excel, and PDF reports. It never runs target code.

Run it from the primary project environment:

```powershell
cd D:\Auditor\Smart_project_auditor
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python audit.py --repo "D:\Path\To\Project" --provider offline --format all
```

Supported providers are `offline`, `nvidia`, and `opencode`; formats are
`json`, `markdown`, `excel`, `pdf`, and `all`. Offline mode needs no network or
key. For hosted providers copy `.env.example` to `.env` and set only the
relevant key: `NVIDIA_API_KEY` or `OPENCODE_API_KEY`. Optional model and
base-URL variables are documented in that file.

NVIDIA NIM and OpenCode Zen both use their OpenAI-compatible chat-completions
interfaces. Provider failures are shown in audit limitations; a managed audit
is recorded as failed and not imported. LLM responses are advisory, strictly
parsed, and never accepted as findings without the required evidence fields.

Run tests with `python -m pytest tests -q`. Treat findings as review input:
static analysis can miss context, LLM results can be rejected, and external
provider use sends only redacted, bounded context subject to client approval.
