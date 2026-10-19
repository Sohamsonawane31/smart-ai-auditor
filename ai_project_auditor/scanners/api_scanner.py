"""
API and Web Application Scanner for AI Project Auditor V2.
Inspects FastAPI, Flask, Django, and Express routes for rate limiting, validation, and error disclosures.
Never executes untrusted code.
"""

import re
from typing import List
from ..models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ..models.technology import TechnologyProfile
from ..security.redactor import SecretRedactor
from .inventory import ProjectInventory


class APIScanner:
    """Deterministic analyzer for Web and API security practices."""

    def __init__(self, inventory: ProjectInventory, profile: TechnologyProfile):
        self.inventory = inventory
        self.profile = profile
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        """Execute API security rules if API frameworks are detected."""
        if not (self.profile.has_api or self.profile.fastapi or self.profile.flask or self.profile.django or self.profile.nodejs):
            return self.findings

        self._check_rate_limiting()
        self._scan_routes_and_error_handling()
        return self.findings

    def _check_rate_limiting(self) -> None:
        """Verify presence of rate limiting middleware or libraries (API-003)."""
        rate_limit_keywords = ["limiter", "slowapi", "ratelimit", "rate_limit", "throttle", "express-rate-limit"]

        found_rate_limiting = False
        for rel_path in self.inventory.python_files + self.inventory.js_ts_files:
            content = self.inventory.read_file(rel_path)
            if not content:
                continue
            content_lower = content.lower()
            if any(kw in content_lower for kw in rate_limit_keywords):
                found_rate_limiting = True
                break

        if not found_rate_limiting:
            self.findings.append(
                Finding(
                    finding_id="",
                    check_id="API-003",
                    title="No API Rate Limiting / Abuse Protection Detected",
                    category="API/Web",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.MEDIUM,
                    file="API Architecture",
                    line=None,
                    evidence="No rate limiting packages (e.g., slowapi, flask-limiter, express-rate-limit) found in codebase.",
                    description="The project exposes API endpoints but lacks visible rate limiting or throttling middleware.",
                    impact="Leaves endpoints vulnerable to brute force attacks, credential stuffing, scraping, and Denial of Service (DoS).",
                    recommendation="Implement rate limiting middleware (such as `slowapi` for FastAPI or `flask-limiter` for Flask).",
                    ai_remediation="Add rate limiter middleware: `from slowapi import Limiter; app.state.limiter = Limiter(key_func=get_remote_address)`.",
                    technology="Web/API",
                    detection_method=DetectionMethod.STATIC,
                )
            )

    def _scan_routes_and_error_handling(self) -> None:
        """Scan API route handlers for verbose error exposure (API-002)."""
        traceback_in_response_pattern = re.compile(
            r"""(?:return|jsonify|Response)\s*\(.*(?:traceback\.format_exc|str\(e\)|repr\(e\)).*""",
            re.IGNORECASE,
        )

        for rel_path in self.inventory.python_files:
            content = self.inventory.read_file(rel_path)
            if not content:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, start=1):
                trimmed = line.strip()
                if traceback_in_response_pattern.search(trimmed):
                    self.findings.append(
                        Finding(
                            finding_id="",
                            check_id="API-002",
                            title="Verbose Exception Traceback Exposed in HTTP Response",
                            category="API/Web",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.HIGH,
                            file=rel_path,
                            line=idx,
                            evidence=SecretRedactor.redact(trimmed),
                            description="Route handler returns raw exception message or traceback directly to API client.",
                            impact="Exposes internal file paths, module structures, database schema hints, and third-party versions to attackers.",
                            recommendation="Catch exceptions, log tracebacks server-side, and return a sanitized generic error message to users.",
                            ai_remediation="Replace with: `logger.exception(e); return {'detail': 'Internal server error'}, 500`.",
                            technology="Web/API",
                            detection_method=DetectionMethod.STATIC,
                        )
                    )
