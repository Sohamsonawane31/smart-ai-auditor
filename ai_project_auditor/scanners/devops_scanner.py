"""
DevOps, Container, and CI/CD Security Scanner for AI Project Auditor V2.
Inspects Dockerfile, docker-compose, and GitHub Actions workflow security.
Never executes untrusted code.
"""

import os
import re
from typing import List
from ..models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ..security.redactor import SecretRedactor
from .inventory import ProjectInventory


class DevOpsScanner:
    """Deterministic analyzer for containers, CI/CD pipelines, and Git hygiene."""

    def __init__(self, inventory: ProjectInventory):
        self.inventory = inventory
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        """Run DevOps and CI/CD inspection rules."""
        self._scan_docker_files()
        self._scan_github_actions()
        self._check_git_hygiene()
        return self.findings

    def _scan_docker_files(self) -> None:
        """Inspect Dockerfile for security misconfigurations (OPS-002)."""
        for rel_path in self.inventory.docker_files:
            fn = os.path.basename(rel_path).lower()
            if not fn.startswith("dockerfile"):
                continue

            content = self.inventory.read_file(rel_path)
            if not content:
                continue

            lines = content.splitlines()
            has_user_instruction = False
            has_healthcheck = False

            for idx, line in enumerate(lines, start=1):
                trimmed = line.strip()
                if not trimmed or trimmed.startswith("#"):
                    continue

                upper = trimmed.upper()
                if upper.startswith("USER ") and not upper.startswith("USER ROOT"):
                    has_user_instruction = True
                if upper.startswith("HEALTHCHECK "):
                    has_healthcheck = True

                # Check unpinned base image (e.g. FROM python:latest or FROM node)
                if upper.startswith("FROM "):
                    parts = trimmed.split()
                    if len(parts) >= 2:
                        image = parts[1]
                        if ":latest" in image or ":" not in image:
                            self.findings.append(
                                Finding(
                                    finding_id="",
                                    check_id="OPS-002",
                                    title=f"Unpinned Base Image in Dockerfile: {image}",
                                    category="DevOps",
                                    severity=FindingSeverity.MEDIUM,
                                    confidence=FindingConfidence.HIGH,
                                    file=rel_path,
                                    line=idx,
                                    evidence=trimmed,
                                    description=f"Dockerfile uses `{image}` without an exact immutable tag or sha256 digest.",
                                    impact="Uncontrolled upstream image changes can introduce vulnerabilities or break container builds.",
                                    recommendation="Pin base images with specific version tags or sha256 hashes (e.g., `python:3.11-slim-bookworm`).",
                                    ai_remediation=f"Update line {idx} to: `FROM {image.split(':')[0]}:<specific_version_or_digest>`.",
                                    technology="Docker",
                                    detection_method=DetectionMethod.STATIC,
                                )
                            )

                # Check hardcoded secrets in ENV
                if upper.startswith("ENV "):
                    if re.search(r"""(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*["']?[a-zA-Z0-9_\-\.~+/]{8,}["']?""", trimmed, re.I):
                        self.findings.append(
                            Finding(
                                finding_id="",
                                check_id="OPS-002",
                                title="Hardcoded Secret in Dockerfile ENV Instruction",
                                category="DevOps",
                                severity=FindingSeverity.CRITICAL,
                                confidence=FindingConfidence.HIGH,
                                file=rel_path,
                                line=idx,
                                evidence=SecretRedactor.redact(trimmed),
                                description="Sensitive credential embedded into image environment layer.",
                                impact="ENV variables persist permanently inside image layers and are inspectable via `docker history`.",
                                recommendation="Inject secrets dynamically at container runtime using Docker secrets or runtime environment files.",
                                ai_remediation="Remove secret from Dockerfile and pass at runtime: `docker run -e SECRET=...`.",
                                technology="Docker",
                                detection_method=DetectionMethod.STATIC,
                            )
                        )

            # Check root user
            if not has_user_instruction:
                self.findings.append(
                    Finding(
                        finding_id="",
                        check_id="OPS-002",
                        title="Container Runs as Default Root User",
                        category="DevOps",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.HIGH,
                        file=rel_path,
                        line=1,
                        evidence="No non-root `USER` instruction found in Dockerfile",
                        description="The Docker container runs as the root user by default without dropping privileges.",
                        impact="A container breakout or application compromise yields root access to the underlying container namespace.",
                        recommendation="Create an unprivileged system user and switch via `USER <username>`.",
                        ai_remediation="Add to Dockerfile: `RUN useradd -m -u 1000 appuser && USER appuser`.",
                        technology="Docker",
                        detection_method=DetectionMethod.STATIC,
                    )
                )

            # Check missing healthcheck
            if not has_healthcheck:
                self.findings.append(
                    Finding(
                        finding_id="",
                        check_id="OPS-002",
                        title="Missing HEALTHCHECK Instruction in Dockerfile",
                        category="DevOps",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        file=rel_path,
                        line=1,
                        evidence="No HEALTHCHECK instruction configured in Dockerfile",
                        description="Dockerfile has no native healthcheck definition to report container health to orchestrators.",
                        impact="Orchestrators (Kubernetes, Docker Swarm) cannot detect hung or zombie containers to trigger auto-restarts.",
                        recommendation="Define a `HEALTHCHECK` instruction verifying HTTP response or process status.",
                        ai_remediation="Add: `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8000/health || exit 1`.",
                        technology="Docker",
                        detection_method=DetectionMethod.STATIC,
                    )
                )

    def _scan_github_actions(self) -> None:
        """Inspect GitHub Actions workflow files for supply chain and script injection risks (OPS-003)."""
        for rel_path in self.inventory.ci_files:
            content = self.inventory.read_file(rel_path)
            if not content:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, start=1):
                trimmed = line.strip()

                # Check pull_request_target with checkout
                if "pull_request_target" in trimmed:
                    self.findings.append(
                        Finding(
                            finding_id="",
                            check_id="OPS-003",
                            title="Dangerous pull_request_target Event in Workflow",
                            category="DevOps",
                            severity=FindingSeverity.HIGH,
                            confidence=FindingConfidence.HIGH,
                            file=rel_path,
                            line=idx,
                            evidence=SecretRedactor.redact(trimmed),
                            description="Workflow triggers on `pull_request_target`, which runs with write permissions and repo secrets.",
                            impact="If PR code is checked out, untrusted external PRs can execute malicious code with repository secret access.",
                            recommendation="Use `pull_request` event for untrusted fork builds, or avoid checking out untrusted PR head refs.",
                            ai_remediation="Switch event to `on: pull_request` unless explicit read-only labeling workflows are intended.",
                            technology="GitHub Actions",
                            detection_method=DetectionMethod.STATIC,
                        )
                    )

                # Check unpinned actions (@master / @main)
                if trimmed.startswith("uses:") and ("@master" in trimmed or "@main" in trimmed):
                    self.findings.append(
                        Finding(
                            finding_id="",
                            check_id="OPS-003",
                            title=f"Unpinned GitHub Action Branch Reference: {trimmed}",
                            category="DevOps",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.HIGH,
                            file=rel_path,
                            line=idx,
                            evidence=SecretRedactor.redact(trimmed),
                            description="Action referenced via mutable branch ref (`@master` or `@main`) instead of immutable commit SHA.",
                            impact="Subject to supply chain hijacking if the upstream repository branch is tampered with or compromised.",
                            recommendation="Pin actions to full 40-character commit SHAs (e.g., `actions/checkout@b4ffde...`).",
                            ai_remediation="Replace branch ref with full commit hash: `uses: action/name@<commit_sha>`.",
                            technology="GitHub Actions",
                            detection_method=DetectionMethod.STATIC,
                        )
                    )

    def _check_git_hygiene(self) -> None:
        """Check for presence and correctness of .gitignore (OPS-004)."""
        gitignore_path = os.path.join(self.inventory.root_path, ".gitignore")
        if not os.path.exists(gitignore_path):
            self.findings.append(
                Finding(
                    finding_id="",
                    check_id="OPS-004",
                    title="Missing .gitignore File in Repository",
                    category="DevOps",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    file=".gitignore",
                    line=None,
                    evidence="No .gitignore file found in repository root.",
                    description="Repository has no root `.gitignore` configuration file.",
                    impact="Accidental commits of credentials, caches, virtual environments, and OS artifacts into version history.",
                    recommendation="Add a standard `.gitignore` tailored to the project stack.",
                    ai_remediation="Create `.gitignore` ignoring `.env`, `__pycache__`, `.venv`, and `node_modules`.",
                    technology="Git",
                    detection_method=DetectionMethod.STATIC,
                )
            )
        else:
            content = self.inventory.read_file(".gitignore") or ""
            content_lower = content.lower()
            missing_critical_ignores = []
            for item in [".env", "__pycache__", ".venv"]:
                if item not in content_lower:
                    missing_critical_ignores.append(item)

            if missing_critical_ignores:
                self.findings.append(
                    Finding(
                        finding_id="",
                        check_id="OPS-004",
                        title=f".gitignore Missing Critical Ignore Entries: {', '.join(missing_critical_ignores)}",
                        category="DevOps",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        file=".gitignore",
                        line=1,
                        evidence=f"Missing patterns: {', '.join(missing_critical_ignores)}",
                        description=f".gitignore file is missing common hygiene patterns: {', '.join(missing_critical_ignores)}.",
                        impact="Elevates risk of staging and committing sensitive environment variables or heavy build artifacts.",
                        recommendation=f"Add {', '.join(missing_critical_ignores)} to `.gitignore`.",
                        ai_remediation=f"Append to `.gitignore`:\n" + "\n".join(missing_critical_ignores),
                        technology="Git",
                        detection_method=DetectionMethod.STATIC,
                    )
                )
