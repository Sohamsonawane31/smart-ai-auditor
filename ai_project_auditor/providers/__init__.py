"""
LLM Providers package for AI Project Auditor V2.
"""

from typing import Optional
from .base import LLMProvider
from .opencode import OpenCodeProvider
from .nvidia import NVIDIAProvider


def get_provider(name: Optional[str]) -> Optional[LLMProvider]:
    """
    Factory to resolve LLM provider instance from CLI string.
    Supported CLI choices: 'offline', 'nvidia', and 'opencode'.
    Returns None for Offline / No LLM mode.
    """
    # The CLI loads configuration earlier, while the Streamlit management UI
    # reaches this factory directly.  Loading here keeps both entry points
    # consistent without adding a third configuration path.
    from ..core.config import AuditorConfig
    AuditorConfig.load_env()
    if not name or name.strip().lower() == "offline":
        return None

    cleaned = name.strip().lower()
    if cleaned == "nvidia":
        return NVIDIAProvider()
    if cleaned == "opencode":
        return OpenCodeProvider()
    raise ValueError(f"Unknown LLM provider '{name}'. Supported providers: 'offline', 'nvidia', 'opencode'.")


__all__ = [
    "LLMProvider",
    "OpenCodeProvider",
    "NVIDIAProvider",
    "get_provider",
]
