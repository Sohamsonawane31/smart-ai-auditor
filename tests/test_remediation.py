from ai_project_auditor.analyzers.remediation import RemediationAssistant
from ai_project_auditor.models.finding import Finding, FindingConfidence, FindingSeverity


def _finding(check_id, category, title):
    return Finding(
        finding_id="FIND-1", check_id=check_id, title=title, category=category,
        severity=FindingSeverity.MEDIUM, confidence=FindingConfidence.HIGH,
        file="src/example.py", line=12, evidence="specific scanner evidence",
        description="Specific issue description", impact="Specific impact", recommendation="Specific scanner recommendation",
    )


def test_dependency_remediation_is_not_generic_security_sanitization():
    guidance = RemediationAssistant.generate_remediation(_finding("DEP-004", "Dependencies", "No Dependency Lockfile Found"))
    assert "lockfile" in guidance.lower()
    assert "sanitization" not in guidance.lower()
    assert "package manager" in guidance.lower()


def test_code_quality_remediation_targets_exception_handling():
    guidance = RemediationAssistant.generate_remediation(_finding("CODE-004", "Code Quality", "Silent Exception Swallowing / Bare Except"))
    assert "exception" in guidance.lower()
    assert "sanitization" not in guidance.lower()
    assert "focused unit tests" in guidance.lower()


def test_testing_remediation_targets_missing_tests():
    guidance = RemediationAssistant.generate_remediation(_finding("TEST-001", "Testing", "No Automated Test Suite Detected"))
    assert "test" in guidance.lower()
    assert "sanitization" not in guidance.lower()


def test_container_remediation_matches_actual_container_finding():
    guidance = RemediationAssistant.generate_remediation(_finding("OPS-002", "DevOps", "Missing HEALTHCHECK Instruction in Dockerfile"))
    assert "health" in guidance.lower()
    assert "appuser" not in guidance.lower()
