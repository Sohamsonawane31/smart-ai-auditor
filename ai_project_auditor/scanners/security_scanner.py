"""
Security scanner — deterministic static analysis for common security vulnerabilities.
"""

import ast
import re
from pathlib import Path
from typing import List

from ai_project_auditor.models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ai_project_auditor.scanners.inventory import ProjectInventory

# Regex for hardcoded credential detection
_SECRET_PATTERNS = [
    (re.compile(r'["\']?(api[_-]?key|secret|password|token|passwd|pwd|auth[_-]?token|access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']', re.IGNORECASE), "SEC-001"),
    (re.compile(r'["\']sk-ant-api[0-9A-Za-z\-]{10,}["\']', re.IGNORECASE), "SEC-001"),
    (re.compile(r'["\']sk-proj-[0-9A-Za-z\-]{10,}["\']', re.IGNORECASE), "SEC-001"),
    (re.compile(r'["\']ghp_[0-9A-Za-z]{10,}["\']', re.IGNORECASE), "SEC-001"),
    (re.compile(r'["\']AKIA[0-9A-Z]{16}["\']'), "SEC-001"),
    (re.compile(r'[0-9a-fA-F]{32,}'), "SEC-001"),  # Generic hex secret
]

_SQL_INJECTION_PATTERNS = re.compile(
    r'execute\s*\(\s*[f"\'].*?\{.*?\}|'
    r'execute\s*\(\s*".*?"\s*\+|'
    r'cursor\.execute\s*\(\s*[f"\'].*?%s',
    re.IGNORECASE,
)

_WEAK_HASH_PATTERN = re.compile(r'\bhashlib\.(md5|sha1)\b', re.IGNORECASE)
_CORS_WILDCARD = re.compile(r'origins\s*=\s*\[.*?["\'\*]["\'].*?\]|CORS.*?allow_origins.*?\*', re.IGNORECASE)
_DEBUG_MODE = re.compile(r'\bdebug\s*=\s*True\b', re.IGNORECASE)

# Dangerous AST call nodes
_DANGEROUS_FUNCS = {"eval", "exec", "__import__"}


class SecurityScanner:
    """Performs deterministic static security analysis."""

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

            findings.extend(self._scan_hardcoded_secrets(content, rel))
            findings.extend(self._scan_dangerous_functions(content, rel))
            findings.extend(self._scan_sql_injection(content, rel))
            findings.extend(self._scan_weak_hash(content, rel))
            findings.extend(self._scan_debug_mode(content, rel))
            findings.extend(self._scan_cors(content, rel))

        return findings

    # ------------------------------------------------------------------ #
    # Individual checks
    # ------------------------------------------------------------------ #

    def _scan_hardcoded_secrets(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, check_id in _SECRET_PATTERNS:
                m = pattern.search(line)
                if m:
                    # Skip obviously test/example values
                    if any(kw in line.lower() for kw in ("example", "placeholder", "your_", "dummy", "fake", "test_", "xxx")):
                        continue
                    # Skip if already redacted
                    if "[REDACTED" in line:
                        continue
                    found.append(Finding(
                        finding_id="",
                        check_id=check_id,
                        title=f"Potential Hardcoded Secret Detected",
                        category="Security",
                        severity=FindingSeverity.CRITICAL,
                        confidence=FindingConfidence.MEDIUM,
                        file=rel,
                        line=line_num,
                        evidence=line.strip()[:200],
                        description="A value resembling an API key, secret, or credential is hardcoded in source.",
                        impact="If this credential is real, it is exposed in version control. Anyone with repository access can use it.",
                        recommendation="Move secrets to environment variables or a secrets manager. Rotate the credential immediately.",
                        technology="General",
                        detection_method=DetectionMethod.STATIC,
                    ))
                    break  # one finding per line max
        return found

    def _scan_dangerous_functions(self, content: str, rel: str) -> List[Finding]:
        found = []
        lines = content.splitlines()
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return found

        for node in ast.walk(tree):
            # `compile()` is deliberately excluded: Python's regular-expression
            # API uses ``re.compile()``, which does not execute source code.
            # These remaining built-ins can evaluate/import attacker-controlled
            # Python and therefore need a security finding.
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in _DANGEROUS_FUNCS:
                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    found.append(Finding(
                        finding_id="",
                        check_id="SEC-004",
                        title=f"Dangerous Function Call: {func_name}()",
                        category="Security",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.HIGH,
                        file=rel,
                        line=node.lineno,
                        evidence=line_content[:200],
                        description=f"`{func_name}()` can evaluate or load attacker-controlled Python and is an injection risk.",
                        impact="Remote code execution if user-controlled data reaches this function.",
                        recommendation=f"Remove `{func_name}()`. Use safe alternatives like `ast.literal_eval()` for data parsing.",
                        technology="Python",
                        detection_method=DetectionMethod.STATIC,
                    ))

            # subprocess with shell=True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "call", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                            found.append(Finding(
                                finding_id="",
                                check_id="SEC-004",
                                title="Shell Injection Risk: subprocess with shell=True",
                                category="Security",
                                severity=FindingSeverity.HIGH,
                                confidence=FindingConfidence.HIGH,
                                file=rel,
                                line=node.lineno,
                                evidence=line_content[:200],
                                description="`subprocess` called with `shell=True` allows shell injection if arguments include user input.",
                                impact="Full command injection and remote code execution.",
                                recommendation="Use `shell=False` (the default) and pass arguments as a list.",
                                technology="Python",
                                detection_method=DetectionMethod.STATIC,
                            ))
                            break

        # pickle.loads
        for line_num, line in enumerate(content.splitlines(), 1):
            if re.search(r'\bpickle\.loads?\s*\(', line):
                found.append(Finding(
                    finding_id="",
                    check_id="SEC-003",
                    title="Insecure Deserialization: pickle.load()",
                    category="Security",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="`pickle.load/loads` deserializes arbitrary Python objects — a code execution vector.",
                    impact="Arbitrary code execution if attacker controls the pickle stream.",
                    recommendation="Use `json`, `msgpack`, or other safe serialization formats.",
                    technology="Python",
                    detection_method=DetectionMethod.STATIC,
                ))

        return found

    def _scan_sql_injection(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _SQL_INJECTION_PATTERNS.search(line):
                found.append(Finding(
                    finding_id="",
                    check_id="SEC-005",
                    title="Potential SQL Injection Risk",
                    category="Security",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.MEDIUM,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="SQL query constructed with string formatting or concatenation — susceptible to injection.",
                    impact="Data exfiltration, privilege escalation, database destruction.",
                    recommendation="Use parameterized queries / prepared statements with `?` or `%s` placeholders.",
                    technology="Python",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _scan_weak_hash(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            m = _WEAK_HASH_PATTERN.search(line)
            if m:
                algo = m.group(1).upper()
                found.append(Finding(
                    finding_id="",
                    check_id="SEC-010",
                    title=f"Weak Cryptographic Hash Algorithm: {algo}",
                    category="Security",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description=f"`{algo}` is a cryptographically broken hash algorithm vulnerable to collision attacks.",
                    impact="Broken integrity checks, hash collisions, insecure password storage.",
                    recommendation="Use `hashlib.sha256()` or `hashlib.sha3_256()` for integrity; use `bcrypt`/`argon2` for passwords.",
                    technology="Python",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _scan_debug_mode(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _DEBUG_MODE.search(line) and not line.strip().startswith("#"):
                found.append(Finding(
                    finding_id="",
                    check_id="SEC-007",
                    title="Debug Mode Enabled in Production Code",
                    category="Security",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="`debug=True` in application code exposes stack traces and interactive debugger to end users.",
                    impact="Information disclosure, potential RCE through debugger (e.g., Werkzeug debugger).",
                    recommendation="Set `debug=False` in production. Control debug via environment variable: `os.getenv('DEBUG', 'False') == 'True'`.",
                    technology="Python",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found

    def _scan_cors(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if _CORS_WILDCARD.search(line):
                found.append(Finding(
                    finding_id="",
                    check_id="SEC-008",
                    title="Wildcard CORS Policy Detected",
                    category="Security",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    file=rel,
                    line=line_num,
                    evidence=line.strip()[:200],
                    description="CORS policy allows all origins (`*`), enabling cross-origin requests from any domain.",
                    impact="CSRF attacks, unauthorized cross-origin API access.",
                    recommendation="Restrict CORS to known, trusted origins. Never use `*` in production APIs.",
                    technology="Python",
                    detection_method=DetectionMethod.STATIC,
                ))
        return found
