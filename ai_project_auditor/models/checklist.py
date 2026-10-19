"""
Checklist item model — one row from the Excel audit checklist.
"""

from dataclasses import dataclass


@dataclass
class ChecklistItem:
    """Represents a single row from the audit checklist Excel file."""
    check_id: str
    category: str
    check: str
    severity: str
    scope: str
    technology: str
    ai_check: bool
    method: str         # "Static" | "LLM" | "Hybrid"
    description: str
    expected_result: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "check": self.check,
            "severity": self.severity,
            "scope": self.scope,
            "technology": self.technology,
            "ai_check": self.ai_check,
            "method": self.method,
            "description": self.description,
            "expected_result": self.expected_result,
        }
