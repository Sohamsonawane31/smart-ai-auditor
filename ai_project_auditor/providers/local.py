"""
Local LLM Provider (Ollama / LocalAI / llama.cpp) for AI Project Auditor V2.
Supports private local model evaluation without cloud data transmission.
"""

import os
from typing import Optional
import requests
from .base import LLMProvider


class LocalProvider(LLMProvider):
    """Local LLM Provider connecting to Ollama or local inference server."""

    def __init__(self, endpoint_url: Optional[str] = None, model: Optional[str] = None):
        self.endpoint_url = (endpoint_url or os.getenv("LOCAL_LLM_URL") or "http://localhost:11434").rstrip("/")
        selected_model = model or os.getenv("LOCAL_MODEL", "llama3.2")
        super().__init__(model=selected_model)

    @property
    def name(self) -> str:
        return f"Local ({self.model} @ {self.endpoint_url})"

    def is_available(self) -> bool:
        """Check if local server is responsive."""
        try:
            resp = requests.get(f"{self.endpoint_url}/api/tags", timeout=2)
            return resp.status_code == 200
        except Exception:
            return False

    def _call_api(self, prompt: str, system_prompt: str) -> Optional[str]:
        # Support Ollama /api/generate
        url = f"{self.endpoint_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt,
            "stream": False,
        }

        try:
            resp = requests.post(url, json=payload, timeout=45)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response")
            return None
        except Exception:
            return None
