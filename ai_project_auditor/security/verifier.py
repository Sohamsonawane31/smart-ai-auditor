"""
Finding Verification and Deduplication Engine for AI Project Auditor V2.
Filters false positives, suppresses marked lines, verifies file locations, and deduplicates findings.
"""

import os
from typing import List, Dict, Optional
from ..models.finding import Finding, FindingConfidence

FALSE_POSITIVE_KEYWORD_PATTERNS = [
    "your_api_key_here",
    "your-api-key-here",
    "insert_key_here",
    "dummy_key",
    "placeholder",
    "change_me",
    "test_token",
    "fake_key",
    "<api_key>",
    "<token>",
    "sk-proj-xxxxxxxx",
    "sk-ant-xxxxxxxx",
    "xxx",
]

SUPPRESSION_MARKERS = [
    "# noqa",
    "# nosec",
    "// eslint-disable",
    "# pragma: no audit",
    "/* audit-ignore */",
    "# auditor: ignore",
]


class FindingVerifier:
    """Verifies candidate findings against project files and suppresses false positives."""

    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)

    def is_false_positive(self, finding: Finding) -> bool:
        """Evaluate if finding is likely a test dummy, placeholder, or explicitly suppressed."""
        evidence_lower = (finding.evidence or "").lower()

        # Check for suppression markers in evidence
        for marker in SUPPRESSION_MARKERS:
            if marker in evidence_lower:
                return True

        # Check for obvious placeholder/dummy credentials
        for kw in FALSE_POSITIVE_KEYWORD_PATTERNS:
            if kw in evidence_lower:
                return True

        return False

    def verify_location(self, finding: Finding) -> bool:
        """Verify the referenced file exists in the repository."""
        if not finding.file:
            return True

        # Allow virtual/project-wide findings
        if finding.file in ("Project", "Architecture", "Dependencies", "Dockerfile", "Repository"):
            return True

        full_path = os.path.join(self.project_root, finding.file)
        return os.path.exists(full_path)

    def verify_and_deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Run verification checks on all candidate findings:
        - Drops false positives and explicit suppressions
        - Deduplicates identical findings (same check_id, file, line)
        - Normalizes finding IDs sequentially (e.g., FIND-001, FIND-002, ...)
        """
        dedup_map: Dict[str, Finding] = {}
        filtered_findings: List[Finding] = []

        for f in findings:
            # Check false positive
            if self.is_false_positive(f):
                continue

            # Verify file exists if physical path
            if not self.verify_location(f):
                f.confidence = FindingConfidence.LOW

            # Key for deduplication
            key = f"{f.check_id}::{f.file}::{f.line or 0}"
            if key not in dedup_map:
                dedup_map[key] = f
                filtered_findings.append(f)
            else:
                # Merge evidence if longer or more confident
                existing = dedup_map[key]
                if len(f.evidence) > len(existing.evidence):
                    existing.evidence = f.evidence

        # Assign clean, standardized sequential finding IDs
        for idx, finding in enumerate(filtered_findings, start=1):
            finding.finding_id = f"FIND-{idx:03d}"
            finding.verified = True

        return filtered_findings
