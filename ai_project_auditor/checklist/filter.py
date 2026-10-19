"""
Checklist filter — dynamically filters checklist items based on detected technology profile.
"""

from typing import List, Tuple

from ai_project_auditor.models.checklist import ChecklistItem
from ai_project_auditor.models.technology import TechnologyProfile


class ChecklistFilter:
    """Filters checklist items to only those applicable to the detected technology profile."""

    @staticmethod
    def filter(
        items: List[ChecklistItem],
        profile: TechnologyProfile,
    ) -> Tuple[List[ChecklistItem], List[ChecklistItem]]:
        """
        Split items into (active_items, skipped_items).

        active_items  — applicable checks that should run
        skipped_items — checks not applicable to this project's tech stack
        """
        active: List[ChecklistItem] = []
        skipped: List[ChecklistItem] = []

        for item in items:
            if ChecklistFilter._is_applicable(item, profile):
                active.append(item)
            else:
                skipped.append(item)

        return active, skipped

    @staticmethod
    def _is_applicable(item: ChecklistItem, profile: TechnologyProfile) -> bool:
        """Return True if this checklist item should be evaluated for this project."""
        tech = item.technology.lower().strip()
        category = item.category.lower().strip()
        check_id = item.check_id.upper()

        # --- AI / LLM / RAG checks ---
        if check_id.startswith("AI-") or item.ai_check:
            return profile.has_ai

        # --- Docker / container checks ---
        if "docker" in tech or check_id in ("OPS-002", "OPS-003"):
            return profile.docker

        # --- GitHub Actions / CI-CD checks ---
        if "github actions" in tech or "ci/cd" in tech or check_id == "OPS-003":
            return profile.github_actions

        # --- React / Next.js specific ---
        if "react" in tech or "next" in tech:
            return profile.react or profile.nextjs

        # --- Node.js specific ---
        if "node" in tech:
            return profile.nodejs or profile.javascript

        # --- Java specific ---
        if "java" in tech and "javascript" not in tech:
            return profile.java

        # --- SQL / database ---
        if "sql" in tech or "database" in tech:
            return profile.sql or profile.python or profile.java

        # --- "All" scope or general checks — always active ---
        if tech in ("all", "", "general", "any"):
            return True

        # --- Python-specific ---
        if "python" in tech:
            return profile.python

        # --- JavaScript / TypeScript ---
        if "javascript" in tech or "typescript" in tech:
            return profile.javascript or profile.typescript

        # Default: include if we can't determine
        return True
