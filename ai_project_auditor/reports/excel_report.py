"""
Excel Report Generator for AI Project Auditor V2.
Produces multi-sheet, styled Excel audit workbooks with severity highlighting using openpyxl.
"""

from pathlib import Path
from typing import Dict, Any
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from ..models.report import AuditReport
from ..security.redactor import SecretRedactor

# Style definitions
HEADER_FONT = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
HEADER_FILL = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
SUBHEADER_FILL = PatternFill(start_color="DCE6F1", end_color="DCE6F1", fill_type="solid")
BOLD_FONT = Font(name="Calibri", size=11, bold=True)
TITLE_FONT = Font(name="Calibri", size=16, bold=True, color="1F497D")

SEVERITY_STYLES = {
    "Critical": {
        "fill": PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="9C0006"),
    },
    "High": {
        "fill": PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="9C6500"),
    },
    "Medium": {
        "fill": PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="7F6000"),
    },
    "Low": {
        "fill": PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid"),
        "font": Font(name="Calibri", size=10, bold=True, color="006100"),
    },
    "Info": {
        "fill": PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid"),
        "font": Font(name="Calibri", size=10, color="595959"),
    },
}

THIN_BORDER = Border(
    left=Side(style="thin", color="D9D9D9"),
    right=Side(style="thin", color="D9D9D9"),
    top=Side(style="thin", color="D9D9D9"),
    bottom=Side(style="thin", color="D9D9D9"),
)


class ExcelReportGenerator:
    """Generates styled Excel workbooks (.xlsx) with findings and checklist status."""

    @classmethod
    def generate(cls, report: AuditReport, output_path: str) -> str:
        wb = openpyxl.Workbook()

        # Sheet 1: Executive Summary
        ws_sum = wb.active
        ws_sum.title = "Executive Summary"
        cls._build_summary_sheet(ws_sum, report)

        # Sheet 2: Findings
        ws_find = wb.create_sheet("Findings")
        cls._build_findings_sheet(ws_find, report)

        # Sheet 3: Checklist Coverage
        ws_cov = wb.create_sheet("Checklist Coverage")
        cls._build_coverage_sheet(ws_cov, report)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        wb.save(str(out.resolve()))
        return str(out.resolve())

    @classmethod
    def _build_summary_sheet(cls, ws, report: AuditReport) -> None:
        ws.views.sheetView[0].showGridLines = True
        stats = report.statistics
        risk = report.risk_summary
        tech = report.technology_profile

        ws["A1"] = "AI Project Auditor V2 - Executive Summary"
        ws["A1"].font = TITLE_FONT

        metadata = [
            ("Project Name", report.project_name),
            ("Project Path", report.project_path),
            ("Audit Date/Time", stats.timestamp),
            ("Ruleset Version", report.checklist_version),
            ("LLM Reasoner", report.llm_provider_used or "Disabled (Deterministic Engine Only)"),
            ("Overall Risk Level", risk.risk_level),
            ("Overall Risk Score", f"{risk.risk_score} / 100"),
        ]

        row_idx = 3
        for label, val in metadata:
            ws.cell(row_idx, 1, label).font = BOLD_FONT
            ws.cell(row_idx, 2, val)
            row_idx += 1

        # Severity breakdown table
        row_idx += 1
        ws.cell(row_idx, 1, "Severity Distribution").font = BOLD_FONT
        ws.cell(row_idx, 2, "Finding Count").font = BOLD_FONT
        ws.cell(row_idx, 1).fill = SUBHEADER_FILL
        ws.cell(row_idx, 2).fill = SUBHEADER_FILL

        sev_rows = [
            ("Critical", risk.critical),
            ("High", risk.high),
            ("Medium", risk.medium),
            ("Low", risk.low),
            ("Info", risk.info),
            ("Total Findings", risk.total),
        ]

        for s_label, count in sev_rows:
            row_idx += 1
            c1 = ws.cell(row_idx, 1, s_label)
            c2 = ws.cell(row_idx, 2, count)
            if s_label in SEVERITY_STYLES:
                c1.fill = SEVERITY_STYLES[s_label]["fill"]
                c1.font = SEVERITY_STYLES[s_label]["font"]
            elif s_label == "Total Findings":
                c1.font = BOLD_FONT
                c2.font = BOLD_FONT

        # Auto fit columns A & B
        ws.column_dimensions["A"].width = 25
        ws.column_dimensions["B"].width = 50

    @classmethod
    def _build_findings_sheet(cls, ws, report: AuditReport) -> None:
        ws.views.sheetView[0].showGridLines = True
        headers = [
            "Finding ID",
            "Check ID",
            "Title",
            "Category",
            "Severity",
            "Confidence",
            "File",
            "Line",
            "Evidence (Redacted)",
            "Description & Why It Matters",
            "Impact",
            "Recommendation",
            "AI Remediation",
            "Technology",
            "Detection Method",
        ]

        for col_idx, header in enumerate(headers, start=1):
            cell = ws.cell(1, col_idx, header)
            cell.font = HEADER_FONT
            cell.fill = HEADER_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

        for row_idx, f in enumerate(report.findings, start=2):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            meth_str = f.detection_method.value if hasattr(f.detection_method, "value") else str(f.detection_method)

            row_data = [
                f.finding_id,
                f.check_id,
                SecretRedactor.redact(f.title),
                f.category,
                sev_str,
                conf_str,
                f.file,
                f.line or "",
                SecretRedactor.redact(f.evidence),
                SecretRedactor.redact(f.description),
                SecretRedactor.redact(f.impact),
                SecretRedactor.redact(f.recommendation),
                SecretRedactor.redact(f.ai_remediation or ""),
                f.technology,
                meth_str,
            ]

            for col_idx, val in enumerate(row_data, start=1):
                cell = ws.cell(row_idx, col_idx, val)
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="top", wrap_text=True)

                if col_idx == 5 and sev_str in SEVERITY_STYLES:  # Severity column
                    cell.fill = SEVERITY_STYLES[sev_str]["fill"]
                    cell.font = SEVERITY_STYLES[sev_str]["font"]

        # Set standard widths
        col_widths = [12, 10, 30, 16, 12, 12, 25, 8, 35, 40, 35, 40, 45, 15, 14]
        for idx, w in enumerate(col_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = w

    @classmethod
    def _build_coverage_sheet(cls, ws, report: AuditReport) -> None:
        ws.views.sheetView[0].showGridLines = True
        headers = ["Check ID", "Category", "Check", "Method", "Status", "Notes"]
        for col_idx, h in enumerate(headers, start=1):
            cell = ws.cell(1, col_idx, h)
            cell.font = HEADER_FONT
            cell.fill = HEADER_FILL

        row_idx = 2
        for result in report.check_results:
            values = [result.check_id, result.category, result.check_name, result.method, result.status, result.notes]
            for col_idx, value in enumerate(values, start=1):
                ws.cell(row_idx, col_idx, value)
            status = ws.cell(row_idx, 5)
            status.font = Font(name="Calibri", color={"PASS": "006100", "FAIL": "9C0006", "SKIPPED": "595959", "ERROR": "9C6500"}.get(result.status, "000000"), bold=True)
            row_idx += 1

        for column, width in zip("ABCDEF", [16, 20, 42, 14, 14, 50]):
            ws.column_dimensions[column].width = width
