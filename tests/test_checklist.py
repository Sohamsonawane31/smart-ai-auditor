"""
Tests for Checklist Reader and Dynamic Filter.
"""

import os
import pytest
from ai_project_auditor.checklist.reader import ChecklistReader
from ai_project_auditor.checklist.filter import ChecklistFilter
from ai_project_auditor.models.technology import TechnologyProfile
from ai_project_auditor.core.exceptions import ChecklistNotFoundError

DEFAULT_CHECKLIST = "config/default_audit_checklist.xlsx"


def test_load_default_checklist():
    assert os.path.exists(DEFAULT_CHECKLIST), "Default audit checklist file must exist in config/"
    reader = ChecklistReader(DEFAULT_CHECKLIST)
    items = reader.load()

    assert len(items) > 50
    check_ids = {it.check_id for it in items}
    assert "SEC-001" in check_ids
    assert "AI-002" in check_ids
    assert "OPS-002" in check_ids
    assert "DEP-001" in check_ids


def test_missing_checklist_raises_error():
    reader = ChecklistReader("non_existent_checklist.xlsx")
    with pytest.raises(ChecklistNotFoundError):
        reader.load()


def test_filter_checklist_for_pure_python():
    reader = ChecklistReader(DEFAULT_CHECKLIST)
    all_items = reader.load()

    profile = TechnologyProfile(python=True, docker=False, llm=False, react=False)
    active, skipped = ChecklistFilter.filter(all_items, profile)

    active_ids = {it.check_id for it in active}
    skipped_ids = {it.check_id for it in skipped}

    # SEC-001 is for All -> must be active
    assert "SEC-001" in active_ids
    # Docker (OPS-002) is False -> must be skipped
    assert "OPS-002" in skipped_ids
    # AI checks (AI-002) -> must be skipped when llm=False
    assert "AI-002" in skipped_ids


def test_filter_checklist_enables_ai_and_docker_when_present():
    reader = ChecklistReader(DEFAULT_CHECKLIST)
    all_items = reader.load()

    profile = TechnologyProfile(python=True, docker=True, llm=True, rag=True, agents=True)
    active, skipped = ChecklistFilter.filter(all_items, profile)

    active_ids = {it.check_id for it in active}

    assert "SEC-001" in active_ids
    assert "OPS-002" in active_ids  # Docker check active
    assert "AI-002" in active_ids   # Prompt injection check active
    assert "AI-006" in active_ids   # RAG check active
