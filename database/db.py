from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from hashlib import pbkdf2_hmac
from pathlib import Path
from secrets import compare_digest, token_bytes
from typing import Any, Dict, List, Optional
from uuid import uuid4

from tinydb import Query, TinyDB

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "audit_db.json"
DB_FILE_PATH = "database/audit_db.json"
LEGACY_PROJECTS_PATH = BASE_DIR / "projects.json"
LEGACY_AUDITS_PATH = BASE_DIR / "audits.json"
_DB: Optional[TinyDB] = None


def _ensure_db_exists() -> Path:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        DB_PATH.touch()
    return DB_PATH


def get_db() -> TinyDB:
    global _DB
    if _DB is None:
        _ensure_db_exists()
        _DB = TinyDB(DB_FILE_PATH, indent=4)
    return _DB


def close_db() -> None:
    global _DB
    if _DB is not None:
        _DB.close()
        _DB = None


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


def _hash_password(password: str) -> str:
    salt = token_bytes(16)
    derived_key = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return (
        "pbkdf2_sha256$200000$"
        f"{base64.b64encode(salt).decode('utf-8')}"
        f"${base64.b64encode(derived_key).decode('utf-8')}"
    )


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, derived_b64 = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected_key = base64.b64decode(derived_b64.encode("utf-8"))
        actual_key = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return compare_digest(actual_key, expected_key)
    except (ValueError, TypeError) as exc:
        return False


def init_db() -> None:
    """Initialize storage and migrate legacy JSON data if needed."""
    db = get_db()
    db.table("projects")
    db.table("audits")
    db.table("settings")
    db.table("users")

    settings_table = db.table("settings")
    migration_complete = settings_table.contains(Query().name == "migration")

    if not migration_complete:
        migrate_legacy_data(db)
        settings_table.insert({"name": "migration", "completed": True, "migrated_at": datetime.now(timezone.utc).isoformat()})


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
        return


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
    return project


def list_projects() -> List[Dict[str, Any]]:
    """Return all stored projects."""
    db = get_db()
    projects = db.table("projects").all()
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
        "auditor": audit_data.get("auditor") or "System",
        "score": audit_data.get("score", _status_to_score(audit_data.get("status", "Pass"))),
        "date": audit_data.get("date") or datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    table.insert(audit)
    return audit


def list_audits() -> List[Dict[str, Any]]:
    """Return all stored audits."""
    db = get_db()
    audits = db.table("audits").all()
    return audits


def get_audits_for_project(project_id: str) -> List[Dict[str, Any]]:
    """Return audit history for a specific project."""
    db = get_db()
    audits = db.table("audits").search(Query().project_id == project_id)
    return audits


def has_users() -> bool:
    """Return True when at least one local user exists."""
    db = get_db()
    return len(db.table("users")) > 0


def create_user(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new local user with a hashed password."""
    db = get_db()
    table = db.table("users")

    username = (user_data.get("username") or "").strip().lower()
    email = (user_data.get("email") or "").strip().lower()
    full_name = (user_data.get("full_name") or "").strip()

    if not username:
        raise ValueError("Username is required")
    if not email:
        raise ValueError("Email is required")
    if not full_name:
        raise ValueError("Full name is required")

    if table.contains(Query().username == username):
        raise ValueError("Username already exists")

    if table.contains(Query().email == email):
        raise ValueError("Email already exists")

    role = user_data.get("role") or ("Admin" if len(table) == 0 else "Auditor")
    user = {
        "id": str(uuid4()),
        "full_name": full_name,
        "username": username,
        "email": email,
        "password_hash": _hash_password(user_data.get("password", "")),
        "role": role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    table.insert(user)
    return {"username": user["username"], "role": user["role"], "full_name": user["full_name"], "email": user["email"]}


def list_users() -> List[Dict[str, Any]]:
    """Return all stored users without exposing hashed passwords."""
    db = get_db()
    users = db.table("users").all()
    return [
        {
            "id": user.get("id"),
            "full_name": user.get("full_name"),
            "username": user.get("username"),
            "email": user.get("email"),
            "role": user.get("role"),
            "created_at": user.get("created_at"),
        }
        for user in users
    ]


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Return a single user by username."""
    db = get_db()
    return db.table("users").get(Query().username == username.strip().lower())


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Return a single user by email."""
    db = get_db()
    return db.table("users").get(Query().email == email.strip().lower())


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Validate username and password against the local TinyDB store."""
    user = get_user_by_username(username)
    if not user:
        return None

    if not _verify_password(password, user.get("password_hash", "")):
        return None

    return {
        "username": user.get("username"),
        "role": user.get("role"),
        "full_name": user.get("full_name"),
        "email": user.get("email"),
    }
