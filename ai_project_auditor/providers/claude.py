"""
Anthropic Claude LLM Provider for AI Project Auditor V2.
Communicates via standard HTTP API to minimize heavy external dependencies.
"""

import os
from typing import Optional
import requests
from .base import LLMProvider


class ClaudeProvider(LLMProvider):
    """Claude provider connecting to Anthropic API."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "").strip()
        selected_model = model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        super().__init__(model=selected_model)

    @property
    def name(self) -> str:
        return f"Claude ({self.model})"

    def is_available(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 10)

    def _call_api(self, prompt: str, system_prompt: str) -> Optional[str]:
        if not self.is_available():
            return None

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                content_blocks = data.get("content", [])
                if content_blocks and "text" in content_blocks[0]:
                    return content_blocks[0]["text"]
            return None
        except Exception:
            return None
