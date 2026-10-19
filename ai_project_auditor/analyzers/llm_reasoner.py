"""
Token-Optimized LLM Reasoning Engine for AI Project Auditor V2.
Evaluates high-level architecture, documentation, and contextual logic for checklist items.
Never sends raw repositories; enforces token limits and secret redaction.
"""

import os
import re
from typing import List, Optional, Dict
from ..models.checklist import ChecklistItem
from ..models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod
from ..models.technology import TechnologyProfile
from ..providers.base import LLMProvider
from ..scanners.inventory import ProjectInventory
from ..security.redactor import SecretRedactor


class LLMReasoner:
    """Orchestrates focused, token-thrifty LLM evaluations for Hybrid and LLM checklist items."""

    def __init__(
        self,
        inventory: ProjectInventory,
        profile: TechnologyProfile,
        provider: Optional[LLMProvider] = None,
    ):
        self.inventory = inventory
        self.profile = profile
        self.provider = provider
        self.findings: List[Finding] = []
        self.llm_stats: Dict = {
            "checks_attempted": 0,
            "checks_succeeded": 0,
            "checks_failed": 0,
            "findings_created": 0,
            "findings_enriched": 0,
            "findings_rejected": 0,
        }

    def reason(
        self, checklist_items: List[ChecklistItem], static_findings_by_check: Dict[str, List[Finding]] = None
    ) -> List[Finding]:
        """
        Evaluate relevant checklist items using the configured LLM provider.

        For Hybrid checks: static analysis runs first and LLM receives only relevant evidence/snippets.
        For LLM-only checks: LLM analyzes code and produces findings.

        Returns list of new findings with correctly set detection_method.
        """
        if not self.provider or not self.provider.is_available():
            self.llm_stats = {
                "checks_attempted": 0,
                "checks_succeeded": 0,
                "checks_failed": 0,
                "findings_created": 0,
                "findings_enriched": 0,
                "findings_rejected": 0,
            }
            return self.findings

        # Separate Hybrid and LLM items
        hybrid_items = [it for it in checklist_items if it.method == "Hybrid"]
        llm_items = [it for it in checklist_items if it.method == "LLM"]

        # Only the bounded set below is actually submitted to a provider.
        self.llm_stats["checks_attempted"] = len(hybrid_items[:3]) + len(llm_items[:3])

        # Process Hybrid checks first: send static evidence to LLM for verification/enrichment
        for item in hybrid_items[:3]:  # Limit to 3 hybrid reasoning checks
            related_static = static_findings_by_check.get(item.check_id, [])
            llm_result = self._reason_hybrid_check(item, related_static)
            self._merge_llm_finding(llm_result, item.method)

        # Process LLM-only checks
        for item in llm_items[:3]:  # Limit to 3 LLM reasoning checks
            llm_result = self._reason_llm_only_check(item)
            self._merge_llm_finding(llm_result, item.method)

        # Normalize stats
        succeeded = self.llm_stats["checks_succeeded"]
        failed = self.llm_stats["checks_failed"]
        self.llm_stats.update(
            {
                "checks_succeeded": succeeded,
                "checks_failed": failed,
            }
        )

        return self.findings

    def _reason_hybrid_check(
        self, item: ChecklistItem, static_findings: List[Finding]
    ) -> Optional[Finding]:
        """
        For Hybrid checks: send static evidence to LLM for verification/enrichment/ rejection.
        LLM can confirm, reject, refine, or create a finding based on the evidence.
        """
        try:
            # Build evidence snippet from static findings
            evidence_snippets = []
            for sf in static_findings:
                if sf.evidence:
                    evidence_snippets.append(f"File: {sf.file} (Line {sf.line}): {sf.evidence[:150]}")
                if sf.description:
                    evidence_snippets.append(f"Description: {sf.description[:200]}")

            evidence_text = "\n".join(evidence_snippets[:5]) if evidence_snippets else "No specific static findings found for this check."

            # Redact any secrets in the evidence
            redacted_evidence = SecretRedactor.redact(evidence_text)

            # Build prompt - send only relevant evidence, not entire repository
            prompt = (
                f"Audit the following evidence strictly for Check ID: {item.check_id} ({item.check}).\n"
                f"Category: {item.category}\n"
                f"Check Description: {item.description}\n"
                f"Severity: {item.severity}\n"
                f"Expected Result: {item.expected_result}\n\n"

                f"EVIDENCE FROM STATIC ANALYSIS:\n"
                f"{redacted_evidence}\n\n"

                f"Based on this evidence, determine:\n"
                f"1. Does the static evidence confirm a genuine issue? (Yes/No)\n"
                f"2. If Yes, provide refined title, line number, impact, and recommendation.\n"
                f"3. If No, the static evidence is insufficient and no LLM finding should be generated.\n"
                f"4. If the static evidence is completely irrelevant to this check, state 'EVIDENCE_IRRELEVANT'.\n\n"

                f"Answer in this EXACT format (choose one):\n"
                f"CONFIRMED: Yes\n"
                f"TITLE: <short title>\n"
                f"LINE: <approximate line number>\n"
                f"DESCRIPTION: <concise explanation based on evidence>\n"
                f"IMPACT: <security/operational impact based on evidence>\n"
                f"RECOMMENDATION: <actionable fix based on evidence>\n\n"
                f"CONFIRMED: No\n"
                f"REASON: <why static evidence is insufficient or issue not found>\n\n"
                f"OR: EVIDENCE_IRRELEVANT\n"
                f"EXPLANATION: <why the static evidence doesn't relate to this check>"
            )

            response = self.provider.generate(
                prompt,
                system_prompt="You are an expert security code auditor. Evaluate only the provided evidence. Do not guess or look for issues outside the given evidence. Report exactly in the specified format.",
            )

            if not response:
                self.llm_stats["checks_failed"] = self.llm_stats.get("checks_failed", 0) + 1
                return None
            self.llm_stats["checks_succeeded"] = self.llm_stats.get("checks_succeeded", 0) + 1

            # Parse response
            result = self._parse_hybrid_response(response, item, static_findings)
            if result:
                self.llm_stats["findings_enriched"] = self.llm_stats.get("findings_enriched", 0) + 1
                return result
            else:
                self.llm_stats["findings_rejected"] = self.llm_stats.get("findings_rejected", 0) + 1
                return None

        except Exception as e:
            self.llm_stats["checks_failed"] = self.llm_stats.get("checks_failed", 0) + 1
            # Log error but don't crash
            return None

    def _reason_llm_only_check(self, item: ChecklistItem) -> Optional[Finding]:
        """
        For LLM-only checks: run LLM analysis on relevant code snippets.
        """
        try:
            # Select focal files for analysis
            focal_files = self._select_focal_files()
            if not focal_files:
                self.llm_stats["findings_rejected"] = self.llm_stats.get("findings_rejected", 0) + 1
                return None

            # Process up to 2 focal files to optimize tokens
            for rel_file in focal_files[:2]:
                content = self.inventory.read_file(rel_file)
                if not content:
                    continue

                # Take compact snippet (max 100 lines) and redact secrets
                lines = content.splitlines()[:100]
                snippet = "\n".join(lines)
                redacted_snippet = SecretRedactor.redact(snippet)

                prompt = (
                    f"Audit the following code snippet strictly for Check ID: {item.check_id} ({item.check}).\n"
                    f"Category: {item.category}\n"
                    f"Check Description: {item.description}\n"
                    f"Expected Result: {item.expected_result}\n\n"
                    f"File: {rel_file}\n"
                    f"```\n{redacted_snippet}\n```\n\n"
                    f"If you detect a genuine, verified issue, answer in this EXACT format:\n"
                    f"ISSUE_FOUND: Yes\n"
                    f"TITLE: <short title>\n"
                    f"LINE: <approximate line number>\n"
                    f"DESCRIPTION: <concise explanation>\n"
                    f"IMPACT: <security/operational impact>\n"
                    f"RECOMMENDATION: <actionable fix>\n"
                    f"Otherwise, output: ISSUE_FOUND: No"
                )

                response = self.provider.generate(
                    prompt,
                    system_prompt="You are an expert static security and code auditor. Report only critical or high verified findings. Do not guess.",
                )

                if response:
                    self.llm_stats["checks_succeeded"] = self.llm_stats.get("checks_succeeded", 0) + 1
                    finding = self._parse_llm_response(response, item, rel_file)
                    if finding:
                        self.llm_stats["findings_created"] = self.llm_stats.get("findings_created", 0) + 1
                        return finding

            if not getattr(self.provider, "last_error", None):
                self.llm_stats["findings_rejected"] = self.llm_stats.get("findings_rejected", 0) + 1
            else:
                self.llm_stats["checks_failed"] = self.llm_stats.get("checks_failed", 0) + 1
            return None

        except Exception:
            self.llm_stats["checks_failed"] = self.llm_stats.get("checks_failed", 0) + 1
            return None

    def _parse_hybrid_response(
        self, response: str, item: ChecklistItem, static_findings: List[Finding]
    ) -> Optional[Finding]:
        """Accept only an explicit LLM confirmation of existing static evidence."""
        try:
            if re.search(r"\bEVIDENCE_IRRELEVANT\b", response or "", re.IGNORECASE):
                return None
            fields = self._structured_fields(response)
            confirmation = self._decision_value(response, "CONFIRMED")
            if not static_findings or confirmation is not True:
                return None
            if not self._has_required_details(fields):
                return None
            line = self._line_number(fields.get("LINE"))
            best_line = next((sf.line for sf in static_findings if isinstance(sf.line, int) and sf.line > 0), line)
            sev = FindingSeverity.CRITICAL if item.severity == "Critical" else FindingSeverity.HIGH
            return Finding(
                finding_id="", check_id=item.check_id, title=f"{item.check_id}: {fields['TITLE']}",
                category=item.category, severity=sev, confidence=FindingConfidence.MEDIUM,
                file=static_findings[0].file, line=best_line,
                evidence="LLM-verified finding based on static evidence", description=fields["DESCRIPTION"],
                impact=fields["IMPACT"], recommendation=fields["RECOMMENDATION"], technology=item.technology,
                detection_method=DetectionMethod.HYBRID, verified=True,
                metadata={"llm_provider": self.provider.name if self.provider else "None", "llm_model": self.provider.model if self.provider else "", "llm_contribution": "verified_and_enriched", "static_findings_count": len(static_findings)},
            )

        except Exception:
            return None

    def _fallback_parse_hybrid(
        self, response: str, item: ChecklistItem, static_findings: List[Finding]
    ) -> Optional[Finding]:
        """Legacy entry point: unconfirmed output is intentionally rejected."""
        return None

    def _parse_llm_response(
        self, response: str, item: ChecklistItem, rel_file: str
    ) -> Optional[Finding]:
        """Extract structured finding from LLM answer (for LLM-only checks)."""
        try:
            fields = self._structured_fields(response)
            if self._decision_value(response, "ISSUE_FOUND") is not True or not self._has_required_details(fields):
                return None
            line = self._line_number(fields.get("LINE"))
            if line is None:
                return None

            sev = FindingSeverity.HIGH if item.severity == "Critical" else FindingSeverity.MEDIUM
            return Finding(
                finding_id="",
                check_id=item.check_id,
                title=f"{item.check_id}: {fields['TITLE']}",
                category=item.category,
                severity=sev,
                confidence=FindingConfidence.MEDIUM,
                file=rel_file,
                line=line,
                evidence="Contextual LLM analysis on module flow",
                description=fields["DESCRIPTION"],
                impact=fields["IMPACT"],
                recommendation=fields["RECOMMENDATION"],
                technology=item.technology,
                detection_method=DetectionMethod.LLM,
                verified=True,
            )
        except Exception:
            return None

    @staticmethod
    def _structured_fields(response: str) -> Dict[str, str]:
        """Parse single-line labelled fields after removing Markdown fences/emphasis."""
        clean = re.sub(r"```(?:\w+)?", "", response or "").replace("**", "").replace("__", "")
        fields: Dict[str, str] = {}
        for raw_line in clean.splitlines():
            line = raw_line.strip().lstrip(">").strip()
            match = re.match(r"(?:[-*]\s*)?(?:\*{1,2})?([A-Za-z_ ]+?)(?:\*{1,2})?\s*[:=\-]\s*(.+?)\s*$", line)
            if match:
                label = re.sub(r"\s+", "_", match.group(1).upper())
                fields[label] = match.group(2).strip().strip("`*")
        return fields

    @classmethod
    def _decision_value(cls, response: str, label: str) -> Optional[bool]:
        clean = re.sub(r"```(?:\w+)?", "", response or "").replace("**", "").replace("__", "")
        values = re.findall(
            rf"(?im)^\s*(?:[-*]\s*)?{re.escape(label)}\s*[:=\-]\s*([^\r\n]+)", clean
        )
        if not values:
            return None
        decisions = set()
        for value in values:
            normalized = value.strip().lower().rstrip(".")
            if normalized in {"yes", "true"}:
                decisions.add(True)
            elif normalized in {"no", "false", "evidence_irrelevant", "not confirmed"}:
                decisions.add(False)
            else:
                return None
        if len(decisions) == 1:
            return decisions.pop()
        return None

    @staticmethod
    def _has_required_details(fields: Dict[str, str]) -> bool:
        return all(fields.get(name, "").strip() for name in ("TITLE", "DESCRIPTION", "IMPACT", "RECOMMENDATION"))

    @staticmethod
    def _line_number(value: Optional[str]) -> Optional[int]:
        match = re.search(r"\b([1-9]\d*)\b", value or "")
        return int(match.group(1)) if match else None

    def _select_focal_files(self) -> List[str]:
        """Select top 1-2 most architecturally significant files in repository."""
        priority_names = ["main.py", "app.py", "server.py", "index.ts", "server.js", "agent.py", "auth.py"]
        selected = []

        for p_name in priority_names:
            for rel in self.inventory.python_files + self.inventory.js_ts_files:
                if os.path.basename(rel).lower() == p_name and rel not in selected:
                    selected.append(rel)
                    if len(selected) >= 2:
                        return selected

        # Fallback to first python file if none found
        if not selected and self.inventory.python_files:
            selected.append(self.inventory.python_files[0])

        return selected

    def _merge_llm_finding(self, finding: Optional[Finding], method: str) -> None:
        """Merge an LLM-generated finding into the findings list with proper detection_method."""
        if finding is None:
            return

        # If finding has a detection_method, use it; otherwise default based on method
        if finding.detection_method == DetectionMethod.HYBRID:
            self.llm_stats["findings_enriched"] = self.llm_stats.get("findings_enriched", 0) + 1
        elif finding.detection_method == DetectionMethod.LLM:
            self.llm_stats["findings_created"] = self.llm_stats.get("findings_created", 0) + 1
        else:
            # Default based on checklist method
            if method == "Hybrid":
                finding.detection_method = DetectionMethod.HYBRID
                self.llm_stats["findings_enriched"] = self.llm_stats.get("findings_enriched", 0) + 1
            else:
                finding.detection_method = DetectionMethod.LLM
                self.llm_stats["findings_created"] = self.llm_stats.get("findings_created", 0) + 1

        self.findings.append(finding)
