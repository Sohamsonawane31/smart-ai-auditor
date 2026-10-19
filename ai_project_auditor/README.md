# Smart AI Auditor engine

This package is the authoritative implementation behind both `audit.py` and
the Streamlit management UI. It inventories a target repository without
executing target code, detects its technology, filters the checklist, runs
deterministic scanners, verifies/deduplicates findings, attaches remediation,
and emits one normalized `AuditReport` for every report format.

## Analysis pipeline

`core.engine.AuditEngine` coordinates project detection, inventory, checklist
filtering, security/dependency/code-quality/test/API/DevOps/AI scanners, finding
verification, remediation, report generators, and local audit history. The
management service imports the JSON output rather than duplicating scanners.

The scanner results are static-first. LLM reasoning is optional and applies only
to selected high-priority checklist items; configuring an AI provider does not
mean every check uses AI. Strict response parsing rejects ambiguous or incomplete
LLM claims.

## CLI

```powershell
python audit.py --repo "D:\Path\To\Project" --provider offline --format all
python audit.py --github "https://github.com/owner/repository" --provider offline --format json
```

Run `python audit.py --help` for the supported `--repo`, `--github`,
`--provider`, `--checklist`, `--format`, `--output`, and `--verbose` arguments.
Supported formats are JSON, Markdown, Excel, PDF, and `all`.

## Providers

`offline` needs no key. `nvidia` reads `NVIDIA_API_KEY` and defaults to
`meta/llama-3.3-70b-instruct`; `opencode` reads `OPENCODE_API_KEY` and defaults
to `kimi-k2.7-code`. Copy the root `.env.example` to `.env`, never commit it,
and obtain approval before transmitting redacted code context externally.

Provider transport failures retain a visible limitation in a CLI report. A
managed audit treats them as a failed run and does not import its report.

## Outputs and tests

The engine produces `*_audit_report.json`, `.md`, `.xlsx`, and `.pdf` in the
chosen output directory. JSON contains project metadata, status/check outcomes,
findings, severity/confidence, evidence, remediation, and LLM execution
metadata; the other formats are rendered from the same report object.

Run engine and scanner tests from the repository root:

```powershell
python -m pytest tests -q
```

Static analysis can miss runtime context, and an LLM result is not proof of a
vulnerability. See the root [product guide](../README.md) and the
[management service guide](management/README.md).
