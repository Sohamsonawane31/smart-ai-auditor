"""Focused strict-but-tolerant parsing tests for remote LLM responses."""

from ai_project_auditor.analyzers.llm_reasoner import LLMReasoner
from ai_project_auditor.models.checklist import ChecklistItem
from ai_project_auditor.models.finding import DetectionMethod, Finding, FindingConfidence, FindingSeverity
from ai_project_auditor.models.technology import TechnologyProfile


def _item(method: str) -> ChecklistItem:
    return ChecklistItem("SEC-001", "Security", "Validate input", "High", "All", "Python", False, method, "Validate untrusted input", "Input is validated")


def _static() -> Finding:
    return Finding("STATIC-1", "SEC-001", "Unsafe input", "Security", FindingSeverity.HIGH, FindingConfidence.HIGH, "app.py", 42, "request data reaches a sink", "Unvalidated input", "Injection", "Validate input")


def test_hybrid_accepts_markdown_confirmation_from_nvidia_style_output():
    response = """```text
**CONFIRMED:** Yes
**TITLE:** Unvalidated request input
**LINE:** 42
**DESCRIPTION:** The supplied static evidence shows request data reaching the sink.
**IMPACT:** An attacker can influence the downstream operation.
**RECOMMENDATION:** Validate and constrain input before the sink.
```"""
    finding = LLMReasoner(None, TechnologyProfile())._parse_hybrid_response(response, _item("Hybrid"), [_static()])
    assert finding is not None
    assert finding.detection_method == DetectionMethod.HYBRID
    assert finding.file == "app.py"
    assert finding.line == 42


def test_hybrid_rejects_ambiguous_or_rejected_responses():
    reasoner = LLMReasoner(None, TechnologyProfile())
    assert reasoner._parse_hybrid_response("The evidence may indicate a problem.", _item("Hybrid"), [_static()]) is None
    assert reasoner._parse_hybrid_response("CONFIRMED: No\nREASON: Insufficient evidence", _item("Hybrid"), [_static()]) is None
    assert reasoner._parse_hybrid_response("CONFIRMED: Yes\nEVIDENCE_IRRELEVANT", _item("Hybrid"), [_static()]) is None
    assert reasoner._parse_hybrid_response("CONFIRMED: Yes\nTITLE: Missing details", _item("Hybrid"), []) is None


def test_llm_accepts_opencode_style_spacing_and_fences():
    response = """```
ISSUE_FOUND = true
TITLE - Missing authorization check
LINE: line 18
DESCRIPTION: The route invokes the sensitive action without an authorization guard.
IMPACT: A low-privileged user could perform an administrative action.
RECOMMENDATION: Enforce authorization before invoking the action.
```"""
    finding = LLMReasoner(None, TechnologyProfile())._parse_llm_response(response, _item("LLM"), "routes.py")
    assert finding is not None
    assert finding.detection_method == DetectionMethod.LLM
    assert finding.line == 18


def test_llm_rejects_ambiguous_or_incomplete_issue_claims():
    reasoner = LLMReasoner(None, TechnologyProfile())
    assert reasoner._parse_llm_response("This might be an issue.", _item("LLM"), "app.py") is None
    assert reasoner._parse_llm_response("ISSUE_FOUND: No", _item("LLM"), "app.py") is None
    assert reasoner._parse_llm_response("ISSUE_FOUND: Yes\nTITLE: Possible issue", _item("LLM"), "app.py") is None
