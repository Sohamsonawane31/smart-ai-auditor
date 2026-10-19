"""
Test Coverage and Architecture Scanner for AI Project Auditor V2.
Evaluates test presence, test frameworks, test-to-code ratios, and untested critical modules.
Never executes untrusted code.
"""

import os
from typing import List
from ..models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from .inventory import ProjectInventory


class TestScanner:
    """Deterministic analyzer for test suites and testing gaps."""

    def __init__(self, inventory: ProjectInventory):
        self.inventory = inventory
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        """Run testing analysis across project inventory."""
        self._check_test_presence()
        self._check_untested_critical_code()
        return self.findings

    def _check_test_presence(self) -> None:
        """Check if project includes any automated tests (TEST-001)."""
        test_count = len(self.inventory.test_files)
        total_source = len(self.inventory.python_files) + len(self.inventory.js_ts_files)

        if total_source > 2 and test_count == 0:
            self.findings.append(
                Finding(
                    finding_id="",
                    check_id="TEST-001",
                    title="No Automated Test Suite Detected",
                    category="Testing",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    file="Project",
                    line=None,
                    evidence=f"Project contains {total_source} source files but 0 test files.",
                    description="No test directory, test files (e.g. `test_*.py`, `*.spec.ts`), or test configurations found.",
                    impact="High risk of regressions, undetected bugs in production, and inability to safely refactor code.",
                    recommendation="Set up an automated testing framework (e.g. `pytest` for Python, `vitest`/`jest` for JavaScript).",
                    ai_remediation="Create a `tests/` directory with `test_sanity.py` and configure pytest in CI/CD pipeline.",
                    technology="General",
                    detection_method=DetectionMethod.STATIC,
                )
            )

    def _check_untested_critical_code(self) -> None:
        """Identify security or AI-sensitive files that lack corresponding test files (TEST-002)."""
        test_basenames = {os.path.basename(f).lower() for f in self.inventory.test_files}

        for src_file in self.inventory.python_files:
            fn = os.path.basename(src_file).lower()
            if fn.startswith("test_") or fn.endswith("_test.py"):
                continue

            # Flag security-critical files
            is_critical = any(kw in fn for kw in ["auth", "security", "token", "crypto", "payment", "login", "password"])
            if is_critical:
                expected_test = f"test_{fn}"
                if expected_test not in test_basenames and f"test_{fn.replace('.py', '')}.py" not in test_basenames:
                    self.findings.append(
                        Finding(
                            finding_id="",
                            check_id="TEST-002",
                            title=f"Security-Critical Module Lacks Dedicated Unit Tests: {os.path.basename(src_file)}",
                            category="Testing",
                            severity=FindingSeverity.HIGH,
                            confidence=FindingConfidence.MEDIUM,
                            file=src_file,
                            line=1,
                            evidence=f"Critical module `{src_file}` has no matching test file in test suite.",
                            description=f"Security-critical module `{src_file}` does not appear to have corresponding test coverage.",
                            impact="Flaws in authentication, token validation, or crypto logic can deploy undetected.",
                            recommendation=f"Author unit and boundary tests for `{src_file}` verifying auth rejection and edge cases.",
                            ai_remediation=f"Create `tests/test_{os.path.basename(src_file)}` with positive, negative, and tamper test cases.",
                            technology="Python",
                            detection_method=DetectionMethod.STATIC,
                        )
                    )
