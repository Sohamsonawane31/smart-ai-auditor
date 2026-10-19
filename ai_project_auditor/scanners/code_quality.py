"""
Code quality scanner — detects excessive file/function size, bare excepts, print statements.
"""

import ast
import re
from typing import List

from ai_project_auditor.models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ai_project_auditor.scanners.inventory import ProjectInventory

_MAX_FILE_LINES = 500
_MAX_FUNC_LINES = 60
_MIN_PRINT_THRESHOLD = 5


class CodeQualityScanner:
    """Detects code quality issues through static analysis."""

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
            lines = content.splitlines()

            findings.extend(self._check_file_size(lines, rel))
            findings.extend(self._check_function_length(content, rel, lines))
            findings.extend(self._check_bare_except(content, rel, lines))
            findings.extend(self._check_print_statements(lines, rel))

        return findings

    def _check_file_size(self, lines: List[str], rel: str) -> List[Finding]:
        n = len(lines)
        if n > _MAX_FILE_LINES:
            return [Finding(
                finding_id="",
                check_id="CODE-003",
                title=f"Excessive File Length ({n} lines)",
                category="Code Quality",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                file=rel,
                line=1,
                evidence=f"File exceeds {_MAX_FILE_LINES} lines (total: {n} lines)",
                description=f"File `{rel}` is overly large, indicating possible violation of Single Responsibility Principle.",
                impact="Reduced readability, high maintenance overhead, and elevated risk of merge conflicts.",
                recommendation="Decompose large module into cohesive submodules or helper classes.",
                technology="Python",
                detection_method=DetectionMethod.STATIC,
            )]
        return []

    def _check_function_length(self, content: str, rel: str, lines: List[str]) -> List[Finding]:
        found = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", node.lineno + 1)
                length = end - node.lineno + 1
                if length > _MAX_FUNC_LINES:
                    func_sig = lines[node.lineno - 1].strip()[:80] if node.lineno <= len(lines) else ""
                    found.append(Finding(
                        finding_id="",
                        check_id="CODE-003",
                        title=f"Excessive Function Length: '{node.name}' ({length} lines)",
                        category="Code Quality",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        file=rel,
                        line=node.lineno,
                        evidence=f"def {node.name}(...): ({length} lines)",
                        description=f"Function `{node.name}` spans {length} lines, exceeding the recommended limit of {_MAX_FUNC_LINES}.",
                        impact="Long functions are difficult to test, reason about, and maintain.",
                        recommendation="Break down function into smaller, well-tested helper functions.",
                        technology="Python",
                        detection_method=DetectionMethod.STATIC,
                    ))
        return found

    def _check_bare_except(self, content: str, rel: str, lines: List[str]) -> List[Finding]:
        found = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if re.match(r'^except\s*:', stripped) or stripped == "except:":
                found.append(Finding(
                    finding_id="",
                    check_id="CODE-004",
                    title="Silent Exception Swallowing / Bare Except",
                    category="Code Quality",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    file=rel,
                    line=line_num,
                    evidence=line.rstrip()[:200],
                    description="Exception handler catches exceptions broadly and suppresses them (e.g., bare `except:` or `pass`).",
                    impact="Masks critical runtime bugs, interrupts, and logic failures, making debugging extremely difficult.",
                    recommendation="Catch specific exceptions, log the error with traceback, and handle or re-raise gracefully.",
                    technology="Python",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _check_print_statements(self, lines: List[str], rel: str) -> List[Finding]:
        count = sum(
            1 for line in lines
            if re.search(r'\bprint\s*\(', line) and not line.strip().startswith("#")
        )
        if count >= _MIN_PRINT_THRESHOLD:
            return [Finding(
                finding_id="",
                check_id="CODE-005",
                title=f"Excessive print() Statements in Production Code ({count} occurrences)",
                category="Code Quality",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                file=rel,
                line=1,
                evidence=f"Found {count} print() calls instead of standard logging",
                description="Standard `print()` calls used extensively instead of configured structured logging.",
                impact="Lacks log levels (INFO, WARN, ERROR), timestamps, formatting, and cannot be filtered or redirected easily.",
                recommendation="Use Python's standard `logging` module or `loguru` for structured log management.",
                technology="Python",
                detection_method=DetectionMethod.STATIC,
            )]
        return []
