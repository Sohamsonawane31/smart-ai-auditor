"""
Dependency scanner — detects known vulnerable, unpinned, and missing lockfile dependencies.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

from ai_project_auditor.models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ai_project_auditor.scanners.inventory import ProjectInventory

# Known vulnerable package versions (package_name_lower: [(vulnerable_version_prefix, CVE, description, severity)])
_KNOWN_VULNERABLE: Dict[str, List[Tuple[str, str, str, str]]] = {
    "jinja2": [
        ("3.0.0", "CVE-2024-22195", "Server-Side Template Injection vulnerability", "High"),
        ("3.0.1", "CVE-2024-22195", "Server-Side Template Injection vulnerability", "High"),
        ("2.", "CVE-2019-10906", "Sandbox escape vulnerability in Jinja2 < 3.x", "High"),
    ],
    "pillow": [
        ("9.0", "CVE-2023-44271", "Uncontrolled resource consumption in Pillow < 10.0", "Medium"),
        ("8.", "CVE-2023-44271", "Uncontrolled resource consumption in Pillow < 10.0", "Medium"),
    ],
    "requests": [
        ("2.19", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.20", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.21", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.22", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.23", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.24", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.25", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.26", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.27", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.28", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.29", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
        ("2.30", "CVE-2023-32681", "Proxy auth header leak in requests < 2.31", "Medium"),
    ],
    "cryptography": [
        ("38.", "CVE-2023-49083", "Null pointer dereference in cryptography < 41.0.6", "Medium"),
        ("39.", "CVE-2023-49083", "Null pointer dereference in cryptography < 41.0.6", "Medium"),
        ("40.", "CVE-2023-49083", "Null pointer dereference in cryptography < 41.0.6", "Medium"),
        ("41.0.0", "CVE-2023-49083", "Null pointer dereference in cryptography < 41.0.6", "Medium"),
    ],
    "pyyaml": [
        ("5.3", "CVE-2020-14343", "Arbitrary code execution via yaml.load() in PyYAML < 5.4", "Critical"),
        ("5.2", "CVE-2020-14343", "Arbitrary code execution via yaml.load() in PyYAML < 5.4", "Critical"),
        ("5.1", "CVE-2020-14343", "Arbitrary code execution via yaml.load() in PyYAML < 5.4", "Critical"),
    ],
    "werkzeug": [
        ("2.2.0", "CVE-2023-46136", "DoS vulnerability in Werkzeug < 2.3.8", "Medium"),
        ("2.2.1", "CVE-2023-46136", "DoS vulnerability in Werkzeug < 2.3.8", "Medium"),
        ("2.2.2", "CVE-2023-46136", "DoS vulnerability in Werkzeug < 2.3.8", "Medium"),
        ("2.2.3", "CVE-2023-46136", "DoS vulnerability in Werkzeug < 2.3.8", "Medium"),
    ],
    "paramiko": [
        ("2.9", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
        ("2.10", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
        ("2.11", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
        ("3.0", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
        ("3.1", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
        ("3.2", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
        ("3.3", "CVE-2023-48795", "Prefix truncation attack (Terrapin) in paramiko < 3.4.0", "Medium"),
    ],
}

_PINNED_PATTERN = re.compile(r'^([A-Za-z0-9_\-\.]+)\s*==\s*([^\s]+)')
_UNPINNED_PATTERN = re.compile(r'^([A-Za-z0-9_\-\.]+)\s*(?:>=|<=|~=|!=|>|<|$)')


class DependencyScanner:
    """Scans dependency files for known CVEs, unpinned versions, and missing lockfiles."""

    def __init__(self, inventory: ProjectInventory) -> None:
        self.inventory = inventory

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        req_file = self._find_file("requirements.txt")
        if req_file:
            content = self.inventory.read_source_file(req_file)
            rel = str(req_file.relative_to(self.inventory.root))
            findings.extend(self._scan_requirements(content, rel))
            findings.extend(self._check_lockfile(req_file))

        pyproject = self._find_file("pyproject.toml")
        if pyproject:
            content = self.inventory.read_source_file(pyproject)
            rel = str(pyproject.relative_to(self.inventory.root))
            findings.extend(self._scan_pyproject(content, rel))

        return findings

    def _find_file(self, name: str) -> Path | None:
        for f in self.inventory.config_files:
            if f.name.lower() == name.lower():
                return f
        return None

    def _scan_requirements(self, content: str, rel: str) -> List[Finding]:
        found = []
        for line_num, raw_line in enumerate(content.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            pinned = _PINNED_PATTERN.match(line)
            if pinned:
                pkg, version = pinned.group(1).lower(), pinned.group(2)
                # Check against known CVEs
                for vuln_prefix, cve, desc, sev in _KNOWN_VULNERABLE.get(pkg, []):
                    if version.startswith(vuln_prefix):
                        found.append(Finding(
                            finding_id="",
                            check_id="DEP-002",
                            title=f"Known Vulnerable Dependency: {pkg}=={version} ({cve})",
                            category="Dependencies",
                            severity=FindingSeverity.from_str(sev),
                            confidence=FindingConfidence.HIGH,
                            file=rel,
                            line=line_num,
                            evidence=line,
                            description=f"{desc}. Package `{pkg}` version `{version}` is affected.",
                            impact=f"Security vulnerability ({cve}) in a direct dependency.",
                            recommendation=f"Upgrade `{pkg}` to the latest secure version. Run `pip install --upgrade {pkg}`.",
                            technology="Python",
                            detection_method=DetectionMethod.STATIC,
                        ))
                        break
            else:
                # Unpinned dependency
                m = _UNPINNED_PATTERN.match(line)
                if m:
                    pkg = m.group(1)
                    found.append(Finding(
                        finding_id="",
                        check_id="DEP-003",
                        title=f"Unpinned Dependency: {pkg}",
                        category="Dependencies",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        file=rel,
                        line=line_num,
                        evidence=line,
                        description=f"Dependency `{pkg}` has no exact version pin. Future installs may pull breaking or vulnerable versions.",
                        impact="Non-reproducible builds, accidental upgrades to incompatible or vulnerable versions.",
                        recommendation=f"Pin to an exact version: `{pkg}==<current_version>`. Use `pip freeze > requirements.txt`.",
                        technology="Python",
                        detection_method=DetectionMethod.STATIC,
                    ))

        return found

    def _scan_pyproject(self, content: str, rel: str) -> List[Finding]:
        """Scan pyproject.toml for unpinned dependencies in [project] dependencies."""
        found = []
        in_deps = False
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if "dependencies" in stripped and "=" in stripped:
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("[") and "dependencies" not in stripped:
                    in_deps = False
                    continue
                if stripped.startswith('"') or stripped.startswith("'"):
                    dep = stripped.strip("\"',[] ")
                    if dep and ">=" in dep and "==" not in dep:
                        pkg = dep.split(">=")[0].strip()
                        found.append(Finding(
                            finding_id="",
                            check_id="DEP-003",
                            title=f"Loosely Pinned Dependency in pyproject.toml: {pkg}",
                            category="Dependencies",
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.MEDIUM,
                            file=rel,
                            line=line_num,
                            evidence=stripped,
                            description=f"`{pkg}` uses `>=` constraint — allows any future version including breaking ones.",
                            impact="Non-reproducible builds, potential breaking upgrades.",
                            recommendation="Consider using exact pinning in a lockfile (poetry.lock, pip-compile) alongside loose constraints.",
                            technology="Python",
                            detection_method=DetectionMethod.STATIC,
                        ))
        return found

    def _check_lockfile(self, req_file: Path) -> List[Finding]:
        """Check if a lockfile (requirements.lock, poetry.lock, etc.) exists."""
        lockfiles = ["requirements.lock", "poetry.lock", "pip-requirements.lock"]
        for lf in lockfiles:
            if (self.inventory.root / lf).exists():
                return []
        return [Finding(
            finding_id="",
            check_id="DEP-004",
            title="No Dependency Lockfile Found",
            category="Dependencies",
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.HIGH,
            file=str(req_file.relative_to(self.inventory.root)),
            line=None,
            evidence="No requirements.lock or poetry.lock found in project root",
            description="Project has a requirements.txt but no lockfile to guarantee reproducible installs.",
            impact="Different environments may install different dependency versions, causing inconsistent behavior.",
            recommendation="Generate a lockfile: `pip-compile requirements.txt` or use `poetry lock`.",
            technology="Python",
            detection_method=DetectionMethod.STATIC,
        )]
