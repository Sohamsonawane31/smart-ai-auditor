"""
Markdown Report Generator for AI Project Auditor V2.
Produces comprehensive, publication-ready GitHub-Flavored Markdown audit reports.
"""

from pathlib import Path
from typing import List, Dict
from ..models.report import AuditReport
from ..models.finding import Finding
from ..security.redactor import SecretRedactor


class MarkdownReportGenerator:
    """Generates styled GitHub-Flavored Markdown audit report."""

    @classmethod
    def generate(cls, report: AuditReport, output_path: str) -> str:
        """Render AuditReport into Markdown and write to output_path."""
        stats = report.statistics
        risk = report.risk_summary
        tech = report.technology_profile

        md_lines: List[str] = []

        # 1. Header & Executive Summary
        md_lines.append(f"# Audit Report: {report.project_name}\n")
        md_lines.append(f"**Audit Timestamp**: {stats.timestamp}  ")
        md_lines.append(f"**Project Location**: `{report.project_path}`  ")
        md_lines.append(f"**Checklist Ruleset**: `{report.checklist_version}`  ")
        md_lines.append(f"**LLM Reasoner**: {report.llm_provider_used or 'Disabled (Deterministic Engine Only)'}\n")

        md_lines.append("## Executive Summary\n")
        md_lines.append(
            f"An automated audit was conducted on **{report.project_name}** using the AI Project Auditor V2 engine. "
            f"The project was evaluated against **{len(report.executed_check_ids)} active audit checks** derived from "
            f"the authoritative Excel checklist. A total of **{len(report.findings)} findings** were identified across "
            f"security, AI/LLM configurations, dependencies, code quality, test coverage, and infrastructure.\n"
        )
        md_lines.append(
            f"> **Overall Risk Assessment**: `{risk.risk_level.upper()}` (Risk Score: **{risk.risk_score} / 100**)\n"
        )

        # 2. Technology Profile
        md_lines.append("## Technology Profile\n")
        md_lines.append(tech.summary_markdown())
        md_lines.append(f"\n- **Total Discovered Files**: {stats.total_files}")
        md_lines.append(f"- **Scanned Code Files**: {stats.scanned_files}")
        md_lines.append(f"- **Estimated Lines of Code**: {stats.total_lines_of_code:,}\n")

        # 3. Severity & Risk Summary
        md_lines.append("## Risk Summary & Severity Breakdown\n")
        md_lines.append("| Severity | Count | Weight Points |")
        md_lines.append("|:---|:---:|:---:|")
        md_lines.append(f"| 🔴 **Critical** | {risk.critical} | 25 pts each |")
        md_lines.append(f"| 🟠 **High**     | {risk.high} | 10 pts each |")
        md_lines.append(f"| 🟡 **Medium**   | {risk.medium} | 4 pts each |")
        md_lines.append(f"| 🔵 **Low**      | {risk.low} | 1 pt each |")
        md_lines.append(f"| ⚪ **Info**     | {risk.info} | 0 pts |")
        md_lines.append(f"| **Total**       | **{risk.total}** | **Score: {risk.risk_score} / 100** |\n")

        md_lines.append("> [!NOTE]")
        md_lines.append(
            "> Risk Score Calculation: `min(100.0, (Critical*25) + (High*10) + (Medium*4) + (Low*1))`. "
            "Individual findings remain transparent and are detailed in full below.\n"
        )

        # 4. Findings Categorized
        md_lines.append("## Detailed Audit Findings\n")

        if not report.findings:
            md_lines.append("✔ **No vulnerabilities or compliance issues were identified during this audit.**\n")
        else:
            # Group by category
            categories: Dict[str, List[Finding]] = {}
            for f in report.findings:
                cat = f.category or "General"
                categories.setdefault(cat, []).append(f)

            for cat_name, cat_findings in categories.items():
                md_lines.append(f"### {cat_name} ({len(cat_findings)} findings)\n")

                for f in cat_findings:
                    sev_emoji = {
                        "Critical": "🔴",
                        "High": "🟠",
                        "Medium": "🟡",
                        "Low": "🔵",
                        "Info": "⚪",
                    }.get(f.severity.value, "🔹")

                    loc_str = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"

                    md_lines.append(f"#### {sev_emoji} [{f.check_id}] {f.title} ({f.finding_id})\n")
                    md_lines.append(f"- **Severity**: `{f.severity.value}` | **Confidence**: `{f.confidence.value}`")
                    md_lines.append(f"- **Location**: {loc_str}")
                    md_lines.append(f"- **Technology**: `{f.technology}` | **Detection**: `{f.detection_method.value}`")
                    md_lines.append(f"- **Verified**: `{'Yes' if f.verified else 'Candidate'}`\n")

                    if f.evidence:
                        md_lines.append("**Evidence**:")
                        md_lines.append("```text")
                        md_lines.append(f.evidence)
                        md_lines.append("```\n")

                    md_lines.append(f"**Description & Why It Matters**:\n{f.description}\n")
                    md_lines.append(f"**Impact**:\n{f.impact}\n")
                    md_lines.append(f"**Recommendation**:\n{f.recommendation}\n")

                    if f.ai_remediation:
                        md_lines.append("**AI Remediation Guidance**:\n")
                        md_lines.append(f.ai_remediation)
                        md_lines.append("\n")

                    md_lines.append("---\n")

        # 5. Production Readiness Assessment
        md_lines.append("## Production Readiness Assessment\n")
        prod_checks = [
            ("Hardcoded Credentials Cleaned", risk.critical == 0, "No critical secret exposure"),
            ("Automated Tests Present", stats.total_files < 3 or not any(c.check_id == "TEST-001" and c.status == "FAIL" for c in report.check_results), "Test suite configuration"),
            ("Container Security Hardened", not tech.docker or all("OPS-002" not in f.check_id or f.severity.value != "Critical" for f in report.findings), "Docker unprivileged user & pinned images"),
            ("API Rate Limiting Active", not tech.has_api or all(f.check_id != "API-003" for f in report.findings), "Rate limiting middleware"),
            ("AI/LLM Injection Protections", not tech.has_ai or all("AI-002" not in f.check_id for f in report.findings), "Prompt injection boundary isolation"),
        ]

        md_lines.append("| Readiness Check | Status | Evaluation |")
        md_lines.append("|:---|:---:|:---|")
        for name, passed, note in prod_checks:
            status_symbol = "✔ PASS" if passed else "✖ ATTENTION"
            md_lines.append(f"| {name} | `{status_symbol}` | {note} |")
        md_lines.append("")

        # 6. Final Recommendations
        md_lines.append("## Top Recommendations\n")
        if risk.critical > 0:
            md_lines.append("1. **Remediate Critical Secrets Immediately**: Rotate exposed credentials and untrack sensitive `.env` files.")
        if any(f.check_id.startswith("AI-") and f.severity.value in ("Critical", "High") for f in report.findings):
            md_lines.append("2. **Fortify AI/LLM Boundaries**: Validate model inputs against prompt injections and sanitize LLM tool execution.")
        if risk.high > 0:
            md_lines.append("3. **Patch High-Risk Injections & Vulnerabilities**: Refactor dynamic SQL queries, eval calls, and outdated dependencies.")
        md_lines.append("4. **Continuous Auditing**: Integrate `ai_project_auditor` into your CI/CD pipeline to prevent regression.")

        full_content = "\n".join(md_lines)
        sanitized_content = SecretRedactor.redact(full_content)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(sanitized_content, encoding="utf-8")
        return str(out.resolve())
