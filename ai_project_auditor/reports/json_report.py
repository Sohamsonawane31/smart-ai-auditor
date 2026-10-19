"""
JSON Report Generator for AI Project Auditor V2.
Produces standardized, machine-readable audit reports.
"""

import json
from pathlib import Path
from typing import Dict, Any
from ..models.report import AuditReport
from ..security.redactor import SecretRedactor


class JSONReportGenerator:
    """Generates formatted JSON audit report."""

    @classmethod
    def generate(cls, report: AuditReport, output_path: str) -> str:
        """Serialize AuditReport to JSON and write to file."""
        data = report.to_dict()
        # Guarantee no secrets leak through raw JSON
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        sanitized_json = SecretRedactor.redact(json_str)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(sanitized_json, encoding="utf-8")
        return str(out.resolve())
