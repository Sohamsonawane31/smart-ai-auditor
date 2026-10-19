"""Generate safe, synthetic report examples for the public repository."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_project_auditor.models.finding import (
    DetectionMethod,
    Finding,
    FindingConfidence,
    FindingSeverity,
)
from ai_project_auditor.models.report import AuditReport, AuditStatistics, CheckResult, CheckStatus, RiskSummary
from ai_project_auditor.models.technology import TechnologyProfile
from ai_project_auditor.reports.excel_report import ExcelReportGenerator
from ai_project_auditor.reports.json_report import JSONReportGenerator
from ai_project_auditor.reports.markdown_report import MarkdownReportGenerator
from ai_project_auditor.reports.pdf_report import PDFReportGenerator


def build_demo_report() -> AuditReport:
    """Return a deliberately non-client report with no credentials or paths."""
    finding = Finding(
        finding_id="DEMO-DEP-001",
        check_id="DEP-003",
        title="Unpinned Dependency (demonstration)",
        category="Dependencies",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        file="requirements.txt",
        line=1,
        evidence="example-library",
        description="This synthetic example shows how an unpinned dependency is reported.",
        impact="Version drift can make builds less reproducible.",
        recommendation="Pin a reviewed compatible version and refresh it through normal dependency maintenance.",
        ai_remediation="Add a reviewed version constraint, test the update, and document the upgrade cadence.",
        technology="Python",
        detection_method=DetectionMethod.STATIC,
        verified=True,
    )
    return AuditReport(
        project_name="smart-ai-auditor-demo",
        project_path="examples/synthetic-demo",
        technology_profile=TechnologyProfile(python=True, primary_language="Python"),
        statistics=AuditStatistics(total_files=3, scanned_files=3, total_lines_of_code=42,
                                   duration_seconds=0.12, timestamp="2026-10-20 00:00:00"),
        risk_summary=RiskSummary.calculate([finding]),
        findings=[finding],
        executed_check_ids=["DEP-003", "SEC-004"],
        skipped_check_ids=["AI-002"],
        check_results=[
            CheckResult("DEP-003", "Dependencies", "Pinned dependencies", "Low", "Static",
                        CheckStatus.FAIL, [finding.finding_id], "Synthetic demonstration finding."),
            CheckResult("SEC-004", "Security", "Dynamic code execution", "High", "Static",
                        CheckStatus.PASS, [], "Synthetic demonstration check passed."),
            CheckResult("AI-002", "AI/LLM", "Prompt injection controls", "High", "LLM",
                        CheckStatus.SKIPPED, [], "Not applicable to the synthetic example."),
        ],
        scanners_used=["Synthetic public example; no repository was scanned."],
        audit_limitations=["This is a documentation asset, not a real audit."],
        audit_source="Synthetic public example",
        checklist_version="demo-checklist",
        file_extension_breakdown={".py": 1, ".txt": 1},
    )


def main() -> None:
    output = ROOT / "reports" / "samples"
    output.mkdir(parents=True, exist_ok=True)
    report = build_demo_report()
    stem = output / "smart-ai-auditor-demo_audit_report"
    JSONReportGenerator.generate(report, str(stem.with_suffix(".json")))
    MarkdownReportGenerator.generate(report, str(stem.with_suffix(".md")))
    ExcelReportGenerator.generate(report, str(stem.with_suffix(".xlsx")))
    PDFReportGenerator.generate(report, str(stem.with_suffix(".pdf")))
    print(f"Generated safe public report samples in {output}")


if __name__ == "__main__":
    main()
