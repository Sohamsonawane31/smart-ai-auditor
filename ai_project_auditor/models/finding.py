"""
Finding data model — the universal unit of audit output.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FindingSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @classmethod
    def from_str(cls, value: str) -> "FindingSeverity":
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        return mapping.get(value.lower(), cls.INFO)


class FindingConfidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @classmethod
    def from_str(cls, value: str) -> "FindingConfidence":
        return {"high": cls.HIGH, "medium": cls.MEDIUM, "low": cls.LOW}.get(
            value.lower(), cls.MEDIUM
        )


class DetectionMethod(str, Enum):
    STATIC = "Static"
    LLM = "LLM"
    HYBRID = "Hybrid"

    @classmethod
    def from_str(cls, value: str) -> "DetectionMethod":
        return {"static": cls.STATIC, "llm": cls.LLM, "hybrid": cls.HYBRID}.get(
            value.lower(), cls.STATIC
        )


@dataclass
class Finding:
    """A single audit finding produced by any scanner."""

    finding_id: str
    check_id: str
    title: str
    category: str
    severity: FindingSeverity
    confidence: FindingConfidence
    file: str
    line: Optional[int]
    evidence: str
    description: str
    impact: str
    recommendation: str
    ai_remediation: str = ""
    technology: str = "General"
    detection_method: DetectionMethod = DetectionMethod.STATIC
    verified: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "ai_remediation": self.ai_remediation,
            "technology": self.technology,
            "detection_method": self.detection_method.value,
            "verified": self.verified,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(
            finding_id=data["finding_id"],
            check_id=data["check_id"],
            title=data["title"],
            category=data["category"],
            severity=FindingSeverity.from_str(data.get("severity", "info")),
            confidence=FindingConfidence.from_str(data.get("confidence", "medium")),
            file=data.get("file", ""),
            line=data.get("line"),
            evidence=data.get("evidence", ""),
            description=data.get("description", ""),
            impact=data.get("impact", ""),
            recommendation=data.get("recommendation", ""),
            ai_remediation=data.get("ai_remediation", ""),
            technology=data.get("technology", "General"),
            detection_method=DetectionMethod.from_str(data.get("detection_method", "static")),
            verified=data.get("verified", False),
            metadata=data.get("metadata", {}),
        )
