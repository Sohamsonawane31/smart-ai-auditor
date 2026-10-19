"""
OpenCode / OpenAI-Compatible LLM Provider for AI Project Auditor V2.
Communicates with OpenAI-compatible endpoints using lightweight HTTP calls.
"""

import os
from typing import Optional
import requests
from .base import LLMProvider
from ..core.exceptions import LLMProviderError


class OpenCodeProvider(LLMProvider):
    """OpenCode / OpenAI-compatible endpoint provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = (api_key if api_key is not None else os.getenv("OPENCODE_API_KEY", "")).strip()
        self.base_url = (base_url if base_url is not None else os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/zen/v1")).rstrip("/")
        selected_model = model if model is not None else os.getenv("OPENCODE_MODEL", "kimi-k2.7-code")
        super().__init__(model=selected_model)

    @property
    def name(self) -> str:
        return f"OpenCode Zen ({self.model})"

    def is_available(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def _call_api(self, prompt: str, system_prompt: str) -> Optional[str]:
        if not self.is_available():
            return None

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 1500,
            "temperature": 0.2,
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
        except requests.Timeout as exc:
            raise LLMProviderError("OpenCode Zen request timed out. Check connectivity or try again.") from exc
        except requests.RequestException as exc:
            raise LLMProviderError("OpenCode Zen network request failed. Check connectivity and endpoint configuration.") from exc
        if resp.status_code != 200:
            detail = {401: "authentication failed", 403: "authorization failed", 429: "rate limit reached"}.get(resp.status_code)
            detail = detail or ("provider service error" if resp.status_code >= 500 else "request was rejected")
            raise LLMProviderError(f"OpenCode Zen API {detail} (HTTP {resp.status_code}).")
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("OpenCode Zen API returned a malformed chat-completion response.") from exc
        if not isinstance(content, str) or not content.strip():
            raise LLMProviderError("OpenCode Zen API returned an empty chat-completion response.")
        return content
