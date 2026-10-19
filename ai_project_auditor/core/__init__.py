"""
Core package — lazy-loads AuditEngine to avoid circular imports.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_project_auditor.core.engine import AuditEngine  # noqa: F401


def __getattr__(name: str):
    if name == "AuditEngine":
        from ai_project_auditor.core.engine import AuditEngine
        return AuditEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["AuditEngine"]
