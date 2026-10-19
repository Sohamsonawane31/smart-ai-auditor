"""Transparent PDF renderer for the normalized :class:`AuditReport`."""

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from ..models.report import AuditReport
from ..security.redactor import SecretRedactor


class PDFReportGenerator:
    """Generate a professional PDF solely from the normalized audit result."""

    @classmethod
    def generate(cls, report: AuditReport, output_path: str) -> str:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(out.resolve()), pagesize=letter, rightMargin=32, leftMargin=32, topMargin=32, bottomMargin=32)
        styles = getSampleStyleSheet()
        title = ParagraphStyle("AuditTitle", parent=styles["Heading1"], fontSize=20, leading=24, textColor=colors.HexColor("#1F497D"))
        h2 = ParagraphStyle("AuditH2", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor("#1F497D"), spaceBefore=12, spaceAfter=6)
        body = ParagraphStyle("AuditBody", parent=styles["Normal"], fontSize=8.5, leading=11)

        def p(value: object, style=body) -> Paragraph:
            return Paragraph(escape(SecretRedactor.redact(str(value or ""))).replace("\n", "<br/>"), style)

        def table(rows, widths=None):
            result = Table(rows, colWidths=widths, repeatRows=1)
            result.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F497D")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#CCCCCC")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            return result

        stats, risk, tech = report.statistics, report.risk_summary, report.technology_profile
        elements = [Paragraph("AI Project Auditor V2 — Audit Report", title), Spacer(1, 6)]

        elements += [Paragraph("Executive Summary", h2)]
        summary_rows = [[p("Metric"), p("Value")],
            [p("Project"), p(report.project_name)], [p("Audit date"), p(stats.timestamp)], [p("Audit source"), p(report.audit_source)],
            [p("Technology detected"), p(tech.primary_language + ("; " + ", ".join(tech.detected_frameworks) if tech.detected_frameworks else ""))],
            [p("LLM provider"), p(report.llm_provider_used or "Not used")], [p("Checklist version"), p(report.checklist_version)],
            [p("Total checks"), p(len(report.check_results) or len(report.executed_check_ids) + len(report.skipped_check_ids))],
            [p("Applicable checks"), p(len(report.executed_check_ids))], [p("Passed"), p(len(report.passed_checks))],
            [p("Failed"), p(len(report.failed_checks))], [p("Skipped / Not Applicable"), p(len(report.skipped_checks))],
            [p("Errors"), p(len(report.error_checks))], [p("Audit duration"), p(f"{stats.duration_seconds:.2f} seconds")]]
        elements += [table(summary_rows, [180, 350]), Spacer(1, 8)]

        elements += [Paragraph("Checklist Coverage", h2)]
        coverage = report.category_coverage()
        coverage_rows = [[p("Category"), p("Pass"), p("Fail"), p("Skipped"), p("Error"), p("Total")]]
        for category, counts in sorted(coverage.items()):
            coverage_rows.append([p(category), p(counts["pass"]), p(counts["fail"]), p(counts["skipped"]), p(counts["error"]), p(counts["total"])])
        if len(coverage_rows) == 1:
            coverage_rows.append([p("No per-check data available"), p("—"), p("—"), p("—"), p("—"), p("—")])
        elements += [table(coverage_rows, [180, 60, 60, 75, 55, 55])]

        elements += [Paragraph("Severity Summary", h2)]
        severity_rows = [[p("Severity"), p("Count")]] + [[p(label), p(count)] for label, count in [
            ("Critical", risk.critical), ("High", risk.high), ("Medium", risk.medium), ("Low", risk.low), ("Info", risk.info)]]
        elements += [table(severity_rows, [180, 100])]
        elements += [p(f"Risk score: {risk.risk_score}/100 ({risk.risk_level}). Formula: min(100, Critical×25 + High×10 + Medium×4 + Low×1)."), Spacer(1, 6)]

        elements += [Paragraph("Technology Profile", h2)]
        flags = [("Python", tech.python), ("FastAPI", tech.fastapi), ("React", tech.react), ("Docker", tech.docker), ("AI/ML", tech.has_ai), ("LLM", tech.llm), ("RAG", tech.rag)]
        elements += [table([[p("Technology"), p("Detected")]] + [[p(n), p("Yes" if value else "No")] for n, value in flags], [180, 100])]

        elements += [Paragraph("Scanners Used", h2)]
        elements += [table([[p("Analysis mechanism"), p("Runtime status")]] + [[p(x.split(":", 1)[0]), p(x.split(":", 1)[1].strip() if ":" in x else x)] for x in report.scanners_used] or [[p("Analysis mechanism"), p("Runtime status")], [p("No scanner telemetry"), p("Not recorded")]], [230, 300])]
        elements += [Paragraph("Audit Limitations", h2)]
        limitations = report.audit_limitations or ["No runtime limitations were recorded."]
        elements += [p("• " + item) for item in limitations]

        elements += [PageBreak(), Paragraph("Checklist Status", h2)]
        status_rows = [[p("Check ID"), p("Category"), p("Status"), p("Notes")]]
        for check in report.check_results:
            status_rows.append([p(check.check_id), p(check.category), p(check.status), p(check.notes)])
        if len(status_rows) == 1:
            status_rows.append([p("No detailed check status available"), p(""), p(""), p("")])
        elements += [table(status_rows, [65, 110, 75, 280])]

        elements += [PageBreak(), Paragraph(f"Findings ({len(report.findings)})", h2)]
        if not report.findings:
            elements.append(p("No verified findings were generated."))
        for finding in report.findings:
            elements += [Paragraph(f"{escape(finding.finding_id)} — {escape(finding.title)}", h2)]
            rows = [[p("Field"), p("Value")], [p("Check ID"), p(finding.check_id)], [p("Category / Severity"), p(f"{finding.category} / {finding.severity.value}")],
                [p("Confidence / verification"), p(f"{finding.confidence.value} / {'Verified' if finding.verified else 'Candidate'}")],
                [p("File / line"), p(f"{finding.file}:{finding.line or ''}")], [p("Evidence"), p(finding.evidence)], [p("Why it matters"), p(finding.description)],
                [p("Impact"), p(finding.impact)], [p("Recommendation"), p(finding.recommendation)], [p("AI remediation"), p(finding.ai_remediation)],
                [p("Technology / detection"), p(f"{finding.technology} / {finding.detection_method.value}")]]
            elements += [table(rows, [145, 390]), Spacer(1, 8)]
        doc.build(elements)
        return str(out.resolve())
