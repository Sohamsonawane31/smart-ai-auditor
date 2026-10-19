"""
Tests for Finding model, serialization, and RiskSummary calculation.
"""

from ai_project_auditor.models.finding import (
    Finding,
    FindingSeverity,
    FindingConfidence,
    DetectionMethod,
)
from ai_project_auditor.models.report import RiskSummary


def test_finding_serialization():
    f = Finding(
        finding_id="FIND-001",
        check_id="SEC-001",
        title="Test Secret",
        category="Security",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        file="app.py",
        line=12,
        evidence="api_key = '[REDACTED]'",
        description="Desc",
        impact="Impact",
        recommendation="Rec",
        ai_remediation="Fix it",
        technology="Python",
        detection_method=DetectionMethod.STATIC,
        verified=True,
    )
    d = f.to_dict()
    assert d["finding_id"] == "FIND-001"
    assert d["severity"] == "Critical"
    assert d["confidence"] == "High"
    assert d["detection_method"] == "Static"

    # Reconstruct
    f2 = Finding.from_dict(d)
    assert f2.finding_id == f.finding_id
    assert f2.severity == FindingSeverity.CRITICAL
    assert f2.detection_method == DetectionMethod.STATIC


def test_risk_summary_scoring_transparent():
    # 1 Critical (25) + 1 High (10) + 2 Medium (8) + 1 Low (1) = 44 points -> Medium Risk Level
    findings = [
        Finding(
            finding_id="1", check_id="SEC-001", title="", category="Security",
            severity=FindingSeverity.CRITICAL, confidence=FindingConfidence.HIGH,
            file="a.py", line=1, evidence="", description="", impact="", recommendation=""
        ),
        Finding(
            finding_id="2", check_id="DEP-002", title="", category="Dependencies",
            severity=FindingSeverity.HIGH, confidence=FindingConfidence.HIGH,
            file="b.py", line=1, evidence="", description="", impact="", recommendation=""
        ),
        Finding(
            finding_id="3", check_id="CODE-004", title="", category="Code Quality",
            severity=FindingSeverity.MEDIUM, confidence=FindingConfidence.HIGH,
            file="c.py", line=1, evidence="", description="", impact="", recommendation=""
        ),
        Finding(
            finding_id="4", check_id="CODE-004", title="", category="Code Quality",
            severity=FindingSeverity.MEDIUM, confidence=FindingConfidence.HIGH,
            file="d.py", line=1, evidence="", description="", impact="", recommendation=""
        ),
        Finding(
            finding_id="5", check_id="DEP-003", title="", category="Dependencies",
            severity=FindingSeverity.LOW, confidence=FindingConfidence.HIGH,
            file="e.py", line=1, evidence="", description="", impact="", recommendation=""
        ),
    ]

    summary = RiskSummary.calculate(findings)
    assert summary.critical == 1
    assert summary.high == 1
    assert summary.medium == 2
    assert summary.low == 1
    assert summary.total == 5
    assert summary.risk_score == 44.0
    assert summary.risk_level == "High"  # Because critical >= 1


def test_risk_summary_zero_findings():
    summary = RiskSummary.calculate([])
    assert summary.total == 0
    assert summary.risk_score == 0.0
    assert summary.risk_level == "Minimal"
