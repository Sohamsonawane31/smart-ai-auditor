"""
Master Audit Engine for AI Project Auditor V2.
Orchestrates the complete audit pipeline: Detection -> Inventory -> Scanners -> Checklist -> LLM -> Verification -> Reports.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from ..models.report import AuditReport, AuditStatistics, RiskSummary, CheckResult, CheckStatus
from ..models.finding import Finding, DetectionMethod
from ..models.technology import TechnologyProfile
from ..models.checklist import ChecklistItem

from ..core.config import AuditorConfig
from ..core.exceptions import InvalidProjectPathError, ReportGenerationError
from ..core.history import AuditHistoryTracker

from ..project_detection.detector import ProjectDetector
from ..checklist.reader import ChecklistReader
from ..checklist.filter import ChecklistFilter
from ..scanners.inventory import ProjectInventory
from ..scanners.security_scanner import SecurityScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.code_quality import CodeQualityScanner
from ..scanners.test_scanner import TestScanner
from ..scanners.api_scanner import APIScanner
from ..scanners.devops_scanner import DevOpsScanner
from ..scanners.ai_scanner import AISecurityScanner

from ..security.redactor import SecretRedactor
from ..security.verifier import FindingVerifier

from ..providers.base import LLMProvider
from ..analyzers.llm_reasoner import LLMReasoner
from ..analyzers.remediation import RemediationAssistant

from ..reports.json_report import JSONReportGenerator
from ..reports.markdown_report import MarkdownReportGenerator
from ..reports.excel_report import ExcelReportGenerator
from ..reports.pdf_report import PDFReportGenerator
from ..utils.logger import get_logger


class AuditEngine:
    """Ties together all static and AI audit capabilities into a unified pipeline."""

    def __init__(
        self,
        project_path: str,
        checklist_path: Optional[str] = None,
        provider: Optional[LLMProvider] = None,
        output_dir: Optional[str] = None,
        formats: Optional[List[str]] = None,
        audit_source: str = "Local repository",
    ):
        self.project_path = os.path.abspath(project_path)
        if not os.path.exists(self.project_path) or not os.path.isdir(self.project_path):
            raise InvalidProjectPathError(self.project_path)

        self.checklist_path = checklist_path or AuditorConfig.DEFAULT_CHECKLIST_PATH
        self.provider = provider
        self.output_dir = output_dir or AuditorConfig.DEFAULT_OUTPUT_DIR
        self.formats = formats or AuditorConfig.DEFAULT_REPORT_FORMATS
        self.audit_source = audit_source
        self.logger = get_logger()

    def run(self) -> Tuple[AuditReport, Dict[str, str]]:
        """
        Execute full audit workflow.
        Returns: (AuditReport, generated_report_files_map)
        """
        start_time = time.time()
        project_name = os.path.basename(self.project_path.rstrip("/\\")) or "AuditedProject"
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.logger.info(f"Starting audit for project: {project_name}")
        self.logger.info(f"Target path: {self.project_path}")

        # 1. Project Detection
        self.logger.info("Detecting technologies and project stack...")
        detector = ProjectDetector(self.project_path)
        tech_profile = detector.detect()
        self.logger.info(f"Primary language detected: {tech_profile.primary_language}")

        # 2. File Inventory
        self.logger.info("Building file inventory with pattern & .gitignore filtering...")
        inventory = ProjectInventory(self.project_path).discover()
        self.logger.info(f"Discovered {len(inventory.all_files)} files to audit.")

        # 3. Load & Filter Excel Checklist
        self.logger.info(f"Loading authoritative audit checklist from: {self.checklist_path}")
        reader = ChecklistReader(self.checklist_path)
        all_checklist_items = reader.load()
        active_items, skipped_items = ChecklistFilter.filter(all_checklist_items, tech_profile)
        active_check_ids = {item.check_id for item in active_items}
        skipped_check_ids = {item.check_id for item in skipped_items}

        self.logger.info(
            f"Checklist filtered: {len(active_items)} active checks, {len(skipped_items)} skipped for this stack."
        )

        # 4. Run Deterministic Scanners
        raw_findings: List[Finding] = []
        scanners_used: List[str] = []
        limitations: List[str] = []

        def run_scanner(name: str, scanner) -> None:
            """Record scanner availability without converting a failed scan into PASS."""
            try:
                raw_findings.extend(scanner.scan())
                scanners_used.append(f"{name}: ran")
            except (OSError, ValueError, SyntaxError) as exc:
                scanners_used.append(f"{name}: failed")
                limitations.append(f"{name} could not complete: {exc}")

        self.logger.info("Running deterministic Security Scanner...")
        run_scanner("Security scanner", SecurityScanner(inventory))

        self.logger.info("Running deterministic Dependency Scanner...")
        run_scanner("Dependency scanner", DependencyScanner(inventory))

        self.logger.info("Running Code Quality & Complexity Scanner...")
        run_scanner("AST/code-quality scanner", CodeQualityScanner(inventory))

        self.logger.info("Running Test Architecture Scanner...")
        run_scanner("Test scanner", TestScanner(inventory))

        if tech_profile.has_api:
            self.logger.info("Running API & Web Security Scanner...")
            run_scanner("API scanner", APIScanner(inventory, tech_profile))
        else:
            limitations.append("API checks were not applicable: no API/web technology was detected.")

        self.logger.info("Running DevOps, Container, and Git Scanner...")
        run_scanner("DevOps and Git scanner", DevOpsScanner(inventory))

        if tech_profile.has_ai:
            self.logger.info("Running AI / LLM / RAG Security Scanner...")
            run_scanner("AI/LLM scanner", AISecurityScanner(inventory))
        else:
            limitations.append("AI/LLM checks were not applicable: no AI technology was detected.")

        # 5. Optional LLM Reasoning
        llm_findings: List[Finding] = []
        llm_stats: Dict = {
            "checks_attempted": 0,
            "checks_succeeded": 0,
            "checks_failed": 0,
            "findings_created": 0,
            "findings_enriched": 0,
            "findings_rejected": 0,
        }

        if self.provider and self.provider.is_available():
            self.logger.info(f"Running LLM reasoning checks with provider: {self.provider.name}...")

            # Debug: check active items
            hybrid_count = sum(
                1 for it in active_items if it.method == "Hybrid" and it.severity in ("Critical", "High")
            )
            llm_count = sum(
                1 for it in active_items if it.method == "LLM" and it.severity in ("Critical", "High")
            )
            self.logger.info(f"Hybrid items: {hybrid_count}, LLM items: {llm_count}")

            # Build mapping of check_id -> static findings for hybrid checks
            static_findings_by_check: Dict[str, List[Finding]] = {}
            for f in raw_findings:
                if f.detection_method == DetectionMethod.STATIC:
                    static_findings_by_check.setdefault(f.check_id, []).append(f)

            self.logger.info(f"Static findings mapped: {len(static_findings_by_check)} check IDs")

            reasoner = LLMReasoner(inventory, tech_profile, self.provider)
            llm_findings = reasoner.reason(active_items, static_findings_by_check)
            llm_stats = reasoner.llm_stats
            self.logger.info(f"LLM findings produced: {len(llm_findings)}")
            self.logger.info(f"LLM stats: {llm_stats}")
            raw_findings.extend(llm_findings)
            if self.provider.last_error:
                scanners_used.append(f"LLM analysis ({self.provider.name}): failed")
                limitations.append(f"LLM provider '{self.provider.name}' failed: {self.provider.last_error}")
            else:
                scanners_used.append(f"LLM analysis ({self.provider.name}): ran")
        elif self.provider:
            self.logger.warning(f"LLM Provider '{self.provider.name}' is unavailable. Continuing deterministically.")
            scanners_used.append(f"LLM analysis ({self.provider.name}): unavailable")
            limitations.append(f"LLM provider '{self.provider.name}' was unavailable; LLM and Hybrid checks were not fully evaluated.")
        else:
            scanners_used.append("LLM analysis: not requested")
            limitations.append("LLM analysis was not requested; LLM-only checklist checks are reported as skipped.")

        # Store LLM stats for report
        self.llm_provider_name = self.provider.name if (self.provider and self.provider.is_available()) else None
        self.llm_model = self.provider.model if (self.provider and self.provider.is_available()) else None
        self.llm_checks_attempted = llm_stats.get("checks_attempted", 0)
        self.llm_checks_succeeded = llm_stats.get("checks_succeeded", 0)
        self.llm_checks_failed = llm_stats.get("checks_failed", 0)
        self.llm_findings_created = llm_stats.get("findings_created", 0)
        self.llm_findings_enriched = llm_stats.get("findings_enriched", 0)
        self.llm_findings_rejected = llm_stats.get("findings_rejected", 0)

        # 6. Filter findings to active checklist rules
        filtered_findings = [f for f in raw_findings if f.check_id in active_check_ids or not active_check_ids]

        # 7. Verification, false-positive filtering, and deduplication
        self.logger.info("Verifying findings and deduplicating...")
        verifier = FindingVerifier(self.project_path)
        verified_findings = verifier.verify_and_deduplicate(filtered_findings)

        # 8. Secret Redaction & Remediation attachment
        self.logger.info("Sanitizing evidence and generating remediation guides...")
        for finding in verified_findings:
            SecretRedactor.redact_finding(finding)
            if not finding.ai_remediation:
                finding.ai_remediation = RemediationAssistant.generate_remediation(finding, self.provider)

        findings_by_check: Dict[str, List[Finding]] = {}
        for finding in verified_findings:
            findings_by_check.setdefault(finding.check_id, []).append(finding)
        failed_scanners = {name.split(":", 1)[0] for name in scanners_used if name.endswith(": failed")}
        check_results: List[CheckResult] = []
        for item in active_items:
            related = findings_by_check.get(item.check_id, [])
            method = item.method.strip().lower()
            if method in ("llm", "hybrid") and self.provider and self.provider.last_error:
                status, notes = CheckStatus.ERROR, f"Configured LLM provider failed: {self.provider.last_error}"
            elif method in ("llm", "hybrid") and not (self.provider and self.provider.is_available()):
                if self.provider:
                    status, notes = CheckStatus.ERROR, "Configured LLM provider was unavailable; this check could not complete."
                else:
                    status, notes = CheckStatus.SKIPPED, "LLM analysis was not requested for this LLM-dependent check."
            elif related:
                status, notes = CheckStatus.FAIL, f"{len(related)} verified finding(s)."
            else:
                # Scanner failures remain visible rather than becoming false PASS results.
                status = CheckStatus.ERROR if failed_scanners else CheckStatus.PASS
                notes = "A scanner failed; this check could not be fully evaluated." if failed_scanners else "Applicable check completed with no verified finding."
            check_results.append(CheckResult(item.check_id, item.category, item.check, item.severity, item.method, status,
                                             [f.finding_id for f in related], notes))
        check_results.extend(CheckResult(item.check_id, item.category, item.check, item.severity, item.method,
                                         CheckStatus.SKIPPED, [], "Not applicable to detected technology.") for item in skipped_items)

        # 9. Risk Summary & Statistics
        risk_summary = RiskSummary.calculate(verified_findings)
        duration = round(time.time() - start_time, 2)

        statistics = AuditStatistics(
            total_files=len(inventory.all_files),
            scanned_files=len(inventory.all_files),
            skipped_files=inventory.skipped_files,
            total_lines_of_code=inventory.total_lines,
            duration_seconds=duration,
            timestamp=timestamp_str,
        )

        report = AuditReport(
            project_name=project_name,
            project_path=self.project_path,
            technology_profile=tech_profile,
            statistics=statistics,
            risk_summary=risk_summary,
            findings=verified_findings,
            executed_check_ids=sorted(list(active_check_ids)),
            skipped_check_ids=sorted(list(skipped_check_ids)),
            check_results=check_results,
            scanners_used=scanners_used,
            audit_limitations=limitations,
            audit_source=self.audit_source,
            llm_provider_used=self.provider.name if (self.provider and self.provider.is_available()) else None,
            llm_model=self.llm_model,
            llm_checks_attempted=self.llm_checks_attempted,
            llm_checks_succeeded=self.llm_checks_succeeded,
            llm_checks_failed=self.llm_checks_failed,
            llm_findings_created=self.llm_findings_created,
            llm_findings_enriched=self.llm_findings_enriched,
            llm_findings_rejected=self.llm_findings_rejected,
            checklist_version=os.path.basename(self.checklist_path),
            file_extension_breakdown=inventory.extension_breakdown,
        )

        # 10. Generate Reports
        generated_files = self._generate_reports(report, project_name)

        # 11. Record history
        tracker = AuditHistoryTracker(self.output_dir)
        tracker.record(report)

        self.logger.info(f"Audit completed in {duration}s with {len(verified_findings)} verified findings.")
        return report, generated_files

    def _generate_reports(self, report: AuditReport, project_name: str) -> Dict[str, str]:
        """Generate reports in all requested formats."""
        out_map: Dict[str, str] = {}
        os.makedirs(self.output_dir, exist_ok=True)
        safe_proj = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project_name)

        # Normalize format requests
        req_formats = [f.strip().lower() for f in self.formats]
        if "all" in req_formats:
            req_formats = ["json", "markdown", "excel", "pdf"]

        for fmt in req_formats:
            try:
                if fmt in ("json",):
                    p = os.path.join(self.output_dir, f"{safe_proj}_audit_report.json")
                    out_map["json"] = JSONReportGenerator.generate(report, p)
                elif fmt in ("markdown", "md"):
                    p = os.path.join(self.output_dir, f"{safe_proj}_audit_report.md")
                    out_map["markdown"] = MarkdownReportGenerator.generate(report, p)
                elif fmt in ("excel", "xlsx"):
                    p = os.path.join(self.output_dir, f"{safe_proj}_audit_report.xlsx")
                    out_map["excel"] = ExcelReportGenerator.generate(report, p)
                elif fmt in ("pdf",):
                    p = os.path.join(self.output_dir, f"{safe_proj}_audit_report.pdf")
                    out_map["pdf"] = PDFReportGenerator.generate(report, p)
            except (OSError, ValueError) as exc:
                raise ReportGenerationError(f"Could not generate requested {fmt} report: {exc}") from exc

        return out_map
