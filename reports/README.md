# Public report assets

`samples/` contains a synthetic, non-client report in JSON, Markdown, Excel,
and PDF. It is generated from `scripts/generate_public_demo_assets.py` and is
safe to publish as an illustration of the report contract.

All other files under the local `reports/` directory are ignored. They can
contain absolute paths, project names, technical findings, or client-sensitive
evidence. Do not add them to Git without a separate privacy review.

Regenerate the public sample from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\generate_public_demo_assets.py
```
