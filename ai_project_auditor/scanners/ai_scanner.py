"""
AI security scanner — detects prompt injection, unsafe LLM output execution,
missing validation, and RAG-specific vulnerabilities.
"""

import re
from typing import List

from ai_project_auditor.models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ai_project_auditor.scanners.inventory import ProjectInventory

_PROMPT_INJECTION = re.compile(
    r'f["\'].*?\{.*?(query|user_input|prompt|request|message|question)\b',
    re.IGNORECASE,
)
_DIRECT_LLM_EXEC = re.compile(
    r'eval\s*\(\s*.*?(response|output|llm|model|result)\b',
    re.IGNORECASE,
)
_UNVALIDATED_JSON = re.compile(
    r'json\.loads\s*\(.*?(response|output|llm|model|result)\b',
    re.IGNORECASE,
)
_UNBOUNDED_LOOP = re.compile(
    r'while\s+True\s*:|for\s+\w+\s+in\s+range\(\s*\)',
    re.IGNORECASE,
)
_RAG_LEAKAGE = re.compile(
    r'(context|retrieved|documents|chunks)\s*=.*?join|\.join.*?(context|retrieved|documents|chunks)',
    re.IGNORECASE,
)


class AISecurityScanner:
    """Scans AI/LLM code for AI-specific security vulnerabilities."""

    def __init__(self, inventory: ProjectInventory) -> None:
        self.inventory = inventory

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        py_files = [f for f in self.inventory.source_files if f.suffix == ".py"]
        py_files += [f for f in self.inventory.config_files
                     if f.suffix == ".py" and f not in py_files]

        for fpath in py_files:
            content = self.inventory.read_source_file(fpath)
            if not content:
                continue
            rel = str(fpath.relative_to(self.inventory.root))

            findings.extend(self._scan_prompt_injection(content, rel))
            findings.extend(self._scan_direct_exec(content, rel))
            findings.extend(self._scan_unvalidated_json(content, rel))
            findings.extend(self._scan_unbounded_loops(content, rel))

        return findings

    def _scan_prompt_injection(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _PROMPT_INJECTION.search(line):
                found.append(Finding(
                    finding_id="",
                    check_id="AI-002",
                    title="Potential Prompt Injection Vulnerability",
                    category="AI/LLM Security",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.MEDIUM,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="User-controlled input appears to be directly interpolated into LLM prompts without sanitization.",
                    impact="Attacker may override system prompt instructions, leak sensitive context, or cause unintended actions.",
                    recommendation="Validate and sanitize user input before insertion into prompts. Use separate system/user message roles. Implement input length limits.",
                    technology="AI/LLM",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _scan_direct_exec(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _DIRECT_LLM_EXEC.search(line):
                found.append(Finding(
                    finding_id="",
                    check_id="AI-004",
                    title="Unsafe Direct Execution of LLM Output",
                    category="AI/LLM Security",
                    severity=FindingSeverity.CRITICAL,
                    confidence=FindingConfidence.HIGH,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="LLM response is passed directly to `eval()` or similar execution function.",
                    impact="Arbitrary code execution. LLM output is untrusted and must never be executed directly.",
                    recommendation="Never execute LLM output. Use structured output formats (JSON schema) and validate strictly.",
                    technology="AI/LLM",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _scan_unvalidated_json(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _UNVALIDATED_JSON.search(line):
                found.append(Finding(
                    finding_id="",
                    check_id="AI-005",
                    title="Unvalidated JSON Parsing of LLM Response",
                    category="AI/LLM Security",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="LLM response parsed with `json.loads()` without schema validation.",
                    impact="Unexpected data structures may cause downstream errors or data corruption.",
                    recommendation="Validate parsed JSON against a strict schema (e.g., Pydantic model) before use.",
                    technology="AI/LLM",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _scan_unbounded_loops(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _UNBOUNDED_LOOP.search(line):
                found.append(Finding(
                    finding_id="",
                    check_id="AI-009",
                    title="Potential Unbounded Agent Loop Detected",
                    category="AI/LLM Security",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.LOW,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="Infinite loop pattern detected in AI/agent code — may run without a maximum iteration limit.",
                    impact="Unbounded token consumption, runaway API costs, denial of service.",
                    recommendation="Add a maximum iteration counter and a break condition for agent loops.",
                    technology="AI/LLM",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found
