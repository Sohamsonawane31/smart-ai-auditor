from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from tinydb import Query, TinyDB

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "audit_db.json"
LEGACY_PROJECTS_PATH = BASE_DIR / "projects.json"
LEGACY_AUDITS_PATH = BASE_DIR / "audits.json"


def _ensure_db_exists() -> Path:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        DB_PATH.touch()
    return DB_PATH


def get_db() -> TinyDB:
    _ensure_db_exists()
    return TinyDB(DB_PATH, indent=4)


def _load_legacy_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _status_to_score(status: str) -> int:
    mapping = {
        "Pass": 100,
        "Partial": 60,
        "Fail": 20,
        "Not Applicable": 100,
    }
    return mapping.get(status, 0)


def init_db() -> None:
    """Initialize storage and migrate legacy JSON data if needed."""
    db = get_db()
    db.table("projects")
    db.table("audits")
    db.table("settings")

    settings_table = db.table("settings")
    migration_complete = settings_table.contains(Query().name == "migration")

    if not migration_complete:
        migrate_legacy_data(db)
        settings_table.insert({"name": "migration", "completed": True, "migrated_at": datetime.now(timezone.utc).isoformat()})
        db.close()
        return

    db.close()


def migrate_legacy_data(db: Optional[TinyDB] = None) -> None:
    """Import existing JSON-based records into TinyDB."""
    should_close = False
    if db is None:
        db = get_db()
        should_close = True

    projects_table = db.table("projects")
    audits_table = db.table("audits")

    if len(projects_table) == 0:
        for project in _load_legacy_json(LEGACY_PROJECTS_PATH):
            projects_table.insert(
                {
                    "id": project.get("id") or str(uuid4()),
                    "name": project.get("name", "Untitled Project"),
                    "client": project.get("client", "Unknown"),
                    "tech": project.get("tech", "Unknown"),
                    "status": project.get("status", "Active"),
                    "created_at": project.get("created_at") or datetime.now(timezone.utc).isoformat(),
                    "updated_at": project.get("updated_at") or datetime.now(timezone.utc).isoformat(),
                }
            )

    if len(audits_table) == 0:
        for audit in _load_legacy_json(LEGACY_AUDITS_PATH):
            audits_table.insert(
                {
                    "id": str(uuid4()),
                    "project_id": audit.get("project_id", ""),
                    "project_name": audit.get("project_name", ""),
                    "category": audit.get("category", "General"),
                    "checkpoint": audit.get("checkpoint", "General Review"),
                    "status": audit.get("status", "Pass"),
                    "severity": audit.get("severity", "Medium"),
                    "remark": audit.get("remark", ""),
                    "score": audit.get("score", _status_to_score(audit.get("status", "Pass"))),
                    "date": audit.get("date") or datetime.now(timezone.utc).isoformat(),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )

    if should_close and db is not None:
        db.close()


def create_project(project_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new project record in TinyDB."""
    db = get_db()
    table = db.table("projects")

    project = {
        "id": project_data.get("id") or str(uuid4()),
        "name": project_data.get("name", "Untitled Project"),
        "client": project_data.get("client", "Unknown"),
        "tech": project_data.get("tech", "Unknown"),
        "status": project_data.get("status", "Active"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    table.insert(project)
    db.close()
    return project


def list_projects() -> List[Dict[str, Any]]:
    """Return all stored projects."""
    db = get_db()
    projects = db.table("projects").all()
    db.close()
    return projects


def save_audit(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """Save a single audit result."""
    db = get_db()
    table = db.table("audits")

    audit = {
        "id": str(uuid4()),
        "project_id": audit_data.get("project_id", ""),
        "project_name": audit_data.get("project_name", ""),
        "category": audit_data.get("category", "General"),
        "checkpoint": audit_data.get("checkpoint", "General Review"),
        "status": audit_data.get("status", "Pass"),
        "severity": audit_data.get("severity", "Medium"),
        "remark": audit_data.get("remark", ""),
        "score": audit_data.get("score", _status_to_score(audit_data.get("status", "Pass"))),
        "date": audit_data.get("date") or datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    table.insert(audit)
    db.close()
    return audit


def list_audits() -> List[Dict[str, Any]]:
    """Return all stored audits."""
    db = get_db()
    audits = db.table("audits").all()
    db.close()
    return audits


def get_audits_for_project(project_id: str) -> List[Dict[str, Any]]:
    """Return audit history for a specific project."""
    db = get_db()
    audits = db.table("audits").search(Query().project_id == project_id)
    db.close()
    return audits
