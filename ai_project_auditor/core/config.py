"""
Auditor configuration loader.
Reads from environment variables and optional .env file.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

# Default checklist path (relative to project root)
DEFAULT_CHECKLIST_PATH = "config/default_audit_checklist.xlsx"
DEFAULT_REPORT_DIR = "reports"
DEFAULT_FORMATS = ["json", "markdown", "excel", "pdf"]
MAX_PROMPT_CHARS = 12000


@dataclass
class AuditorConfig:
    """Holds all runtime configuration for an audit session."""

    # Paths
    checklist_path: str = DEFAULT_CHECKLIST_PATH
    report_dir: str = DEFAULT_REPORT_DIR

    # Output formats
    formats: list = field(default_factory=lambda: ["json", "markdown", "excel", "pdf"])

    # LLM provider
    provider_name: str = "none"

    # Verbosity
    verbose: bool = False

    # LLM API keys (loaded from env)
    nvidia_api_key: str = ""
    opencode_api_key: str = ""

    # Class-level defaults retained for the engine/CLI public API.
    DEFAULT_CHECKLIST_PATH = DEFAULT_CHECKLIST_PATH
    DEFAULT_OUTPUT_DIR = DEFAULT_REPORT_DIR
    DEFAULT_REPORT_FORMATS = DEFAULT_FORMATS

    @classmethod
    def load_env(cls) -> None:
        """Load a local .env file without overwriting the process environment."""
        _load_dotenv()

    @classmethod
    def from_env(cls) -> "AuditorConfig":
        """Build configuration from environment variables, loading .env if present."""
        _load_dotenv()
        return cls(
            checklist_path=os.environ.get("AUDIT_CHECKLIST_PATH", DEFAULT_CHECKLIST_PATH),
            report_dir=os.environ.get("AUDIT_REPORT_DIR", DEFAULT_REPORT_DIR),
            nvidia_api_key=os.environ.get("NVIDIA_API_KEY", ""),
            opencode_api_key=os.environ.get("OPENCODE_API_KEY", ""),
        )


def _load_dotenv() -> None:
    """Minimal .env loader — no external dependency required."""
    candidates = (Path(".env"), Path(__file__).resolve().parents[2] / ".env")
    dotenv_path = next((path for path in candidates if path.exists()), None)
    if dotenv_path is None:
        return
    with dotenv_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
