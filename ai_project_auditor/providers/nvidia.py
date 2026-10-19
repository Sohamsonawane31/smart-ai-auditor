"""NVIDIA NIM provider using its documented OpenAI-compatible endpoint."""

import os
from typing import Optional
import requests
from .base import LLMProvider
from ..core.exceptions import LLMProviderError


class NVIDIAProvider(LLMProvider):
    """NVIDIA hosted NIM chat-completions provider."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = (api_key if api_key is not None else os.getenv("NVIDIA_API_KEY", "")).strip()
        self.base_url = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
        selected_model = model if model is not None else os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct")
        super().__init__(model=selected_model)

    @property
    def name(self) -> str:
        return f"NVIDIA ({self.model})"

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
            raise LLMProviderError("NVIDIA request timed out. Check connectivity or try again.") from exc
        except requests.RequestException as exc:
            raise LLMProviderError("NVIDIA network request failed. Check connectivity and NVIDIA endpoint configuration.") from exc
        if resp.status_code != 200:
            detail = {401: "authentication failed", 403: "authorization failed", 429: "rate limit reached"}.get(resp.status_code)
            detail = detail or ("provider service error" if resp.status_code >= 500 else "request was rejected")
            raise LLMProviderError(f"NVIDIA API {detail} (HTTP {resp.status_code}).")
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("NVIDIA API returned a malformed chat-completion response.") from exc
        if not isinstance(content, str) or not content.strip():
            raise LLMProviderError("NVIDIA API returned an empty chat-completion response.")
        return content
