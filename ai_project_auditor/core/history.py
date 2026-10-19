"""
Audit history tracker — persists a summary of every audit to audit_history.json.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_project_auditor.models.report import AuditReport

HISTORY_FILENAME = "audit_history.json"


class AuditHistoryTracker:
    """Appends a compact record of each audit to audit_history.json."""

    def __init__(self, report_dir: str) -> None:
        self.history_path = Path(report_dir) / HISTORY_FILENAME

    def record(self, report: "AuditReport") -> None:
        """Append this report's summary to the history file."""
        history = self._load()
        entry = {
            "timestamp": report.statistics.timestamp,
            "project_name": report.project_name,
            "project_path": str(report.project_path),
            "risk_level": report.risk_summary.risk_level,
            "risk_score": report.risk_summary.risk_score,
            "total_findings": report.risk_summary.total,
            "critical": report.risk_summary.critical,
            "high": report.risk_summary.high,
            "medium": report.risk_summary.medium,
            "low": report.risk_summary.low,
            "total_checks_executed": len(report.executed_check_ids),
            "total_checks_skipped": len(report.skipped_check_ids),
            "llm_provider": report.llm_provider_used or "none",
            "duration_seconds": report.statistics.duration_seconds,
        }
        history.append(entry)
        self._save(history)

    def _load(self) -> list:
        if self.history_path.exists():
            try:
                with self.history_path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self, history: list) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
