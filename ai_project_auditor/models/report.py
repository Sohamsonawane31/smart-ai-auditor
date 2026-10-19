"""
Audit report models — AuditReport, AuditStatistics, RiskSummary, CheckResult.

New in v2: CheckResult tracks per-check PASS/FAIL/SKIPPED/ERROR status,
enabling full checklist coverage reporting.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ai_project_auditor.models.finding import Finding
    from ai_project_auditor.models.technology import TechnologyProfile


# ---------------------------------------------------------------------------
# CheckResult — per-check PASS / FAIL / SKIPPED / ERROR
# ---------------------------------------------------------------------------

class CheckStatus:
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    """
    The outcome of a single checklist item for this audit.

    status:
        PASS    — the check ran and found no issues
        FAIL    — the check found at least one finding
        SKIPPED — the check was not applicable for this project's tech stack
        ERROR   — the check could not complete due to a scanner error
    """
    check_id: str
    category: str
    check_name: str
    severity: str
    method: str                         # Static | LLM | Hybrid
    status: str                         # CheckStatus constant
    finding_ids: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "check_name": self.check_name,
            "severity": self.severity,
            "method": self.method,
            "status": self.status,
            "finding_ids": self.finding_ids,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# RiskSummary — transparent score calculation
# ---------------------------------------------------------------------------

@dataclass
class RiskSummary:
    """Aggregated risk counts and transparent risk score."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    risk_score: float = 0.0
    risk_level: str = "Minimal"
    category_breakdown: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @classmethod
    def calculate(cls, findings: List["Finding"]) -> "RiskSummary":
        """
        Transparent scoring formula:
          score = min(100, Critical*25 + High*10 + Medium*4 + Low*1)

        Risk level:
          Critical >= 1            -> Critical
          High >= 1 or score >= 40 -> High
          score >= 20              -> Medium
          score >= 5               -> Low
          else                     -> Minimal
        """
        from ai_project_auditor.models.finding import FindingSeverity

        counts = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 0,
            FindingSeverity.MEDIUM: 0,
            FindingSeverity.LOW: 0,
            FindingSeverity.INFO: 0,
        }
        cat_breakdown: Dict[str, Dict[str, int]] = {}

        for f in findings:
            counts[f.severity] += 1
            cat = f.category
            if cat not in cat_breakdown:
                cat_breakdown[cat] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            cat_breakdown[cat][f.severity.value] += 1

        score = min(
            100.0,
            counts[FindingSeverity.CRITICAL] * 25
            + counts[FindingSeverity.HIGH] * 10
            + counts[FindingSeverity.MEDIUM] * 4
            + counts[FindingSeverity.LOW] * 1,
        )

        if counts[FindingSeverity.CRITICAL] >= 1 or counts[FindingSeverity.HIGH] >= 1 or score >= 40:
            level = "High"
        elif score >= 20:
            level = "Medium"
        elif score >= 5:
            level = "Low"
        else:
            level = "Minimal"

        return cls(
            critical=counts[FindingSeverity.CRITICAL],
            high=counts[FindingSeverity.HIGH],
            medium=counts[FindingSeverity.MEDIUM],
            low=counts[FindingSeverity.LOW],
            info=counts[FindingSeverity.INFO],
            total=len(findings),
            risk_score=score,
            risk_level=level,
            category_breakdown=cat_breakdown,
        )

    def to_dict(self) -> dict:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "total": self.total,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "category_breakdown": self.category_breakdown,
        }


# ---------------------------------------------------------------------------
# AuditStatistics
# ---------------------------------------------------------------------------

@dataclass
class AuditStatistics:
    """Lightweight scan statistics (timing, file counts)."""

    total_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0
    total_lines_of_code: int = 0
    duration_seconds: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "total_lines_of_code": self.total_lines_of_code,
            "duration_seconds": round(self.duration_seconds, 2),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# AuditReport — the master report container
# ---------------------------------------------------------------------------

@dataclass
class AuditReport:
    """
    Master container for all audit results.

    New fields (v2 transparency improvements):
        check_results    — per-check PASS/FAIL/SKIPPED/ERROR outcomes
        scanners_used    — list of scanner names that actually ran
        audit_limitations — descriptions of checks/areas that couldn't run
    """

    project_name: str
    project_path: str
    technology_profile: "TechnologyProfile"
    statistics: AuditStatistics
    risk_summary: RiskSummary
    findings: List["Finding"]
    executed_check_ids: List[str]
    skipped_check_ids: List[str]

    # NEW — transparency fields
    check_results: List[CheckResult] = field(default_factory=list)
    scanners_used: List[str] = field(default_factory=list)
    audit_limitations: List[str] = field(default_factory=list)
    audit_source: str = "Local repository"

    # Metadata
    llm_provider_used: Optional[str] = None
    llm_model: Optional[str] = None
    llm_checks_attempted: int = 0
    llm_checks_succeeded: int = 0
    llm_checks_failed: int = 0
    llm_findings_created: int = 0
    llm_findings_enriched: int = 0
    llm_findings_rejected: int = 0
    checklist_version: str = "default_audit_checklist.xlsx"
    file_extension_breakdown: Dict[str, int] = field(default_factory=dict)

    # ---------------------------------------------------------------------------
    # Computed summary helpers
    # ---------------------------------------------------------------------------

    @property
    def passed_checks(self) -> List[CheckResult]:
        return [c for c in self.check_results if c.status == CheckStatus.PASS]

    @property
    def failed_checks(self) -> List[CheckResult]:
        return [c for c in self.check_results if c.status == CheckStatus.FAIL]

    @property
    def skipped_checks(self) -> List[CheckResult]:
        return [c for c in self.check_results if c.status == CheckStatus.SKIPPED]

    @property
    def error_checks(self) -> List[CheckResult]:
        return [c for c in self.check_results if c.status == CheckStatus.ERROR]

    def category_coverage(self) -> Dict[str, dict]:
        """
        Returns per-category coverage summary:
          { "Security": {"pass": 8, "fail": 2, "skipped": 0, "error": 0, "total": 10} }
        """
        cats: Dict[str, dict] = {}
        for cr in self.check_results:
            cat = cr.category
            if cat not in cats:
                cats[cat] = {"pass": 0, "fail": 0, "skipped": 0, "error": 0, "total": 0}
            cats[cat]["total"] += 1
            if cr.status == CheckStatus.PASS:
                cats[cat]["pass"] += 1
            elif cr.status == CheckStatus.FAIL:
                cats[cat]["fail"] += 1
            elif cr.status == CheckStatus.SKIPPED:
                cats[cat]["skipped"] += 1
            elif cr.status == CheckStatus.ERROR:
                cats[cat]["error"] += 1
        return cats

    def to_dict(self) -> dict:
        return {
            "project_name": self.project_name,
            "project_path": str(self.project_path),
            "technology_profile": self.technology_profile.to_dict(),
            "file_extension_breakdown": self.file_extension_breakdown,
            "statistics": self.statistics.to_dict(),
            "risk_summary": self.risk_summary.to_dict(),
            "check_results": [cr.to_dict() for cr in self.check_results],
            "executed_check_ids": self.executed_check_ids,
            "skipped_check_ids": self.skipped_check_ids,
            "scanners_used": self.scanners_used,
            "audit_limitations": self.audit_limitations,
            "audit_source": self.audit_source,
            "llm_provider_used": self.llm_provider_used,
            "llm_model": self.llm_model,
            "llm_checks_attempted": self.llm_checks_attempted,
            "llm_checks_succeeded": self.llm_checks_succeeded,
            "llm_checks_failed": self.llm_checks_failed,
            "llm_findings_created": self.llm_findings_created,
            "llm_findings_enriched": self.llm_findings_enriched,
            "llm_findings_rejected": self.llm_findings_rejected,
            "checklist_version": self.checklist_version,
            "findings": [f.to_dict() for f in self.findings],
        }
