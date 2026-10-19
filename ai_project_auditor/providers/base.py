"""
LLM Provider Base Interface and Token Optimizer for AI Project Auditor V2.
Enforces strict secret redaction, token budgeting, prompt caching, and graceful failure handling.
"""

import hashlib
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from ..security.redactor import SecretRedactor
from ..core.exceptions import LLMProviderError

MAX_PROMPT_CHARS = 12_000  # Conservative context ceiling (~3,000 tokens) to minimize cost


class LLMProvider(ABC):
    """Abstract base class for all LLM providers."""

    def __init__(self, model: str = ""):
        self.model = model
        self._cache: Dict[str, str] = {}
        self.last_error: Optional[str] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider credentials/endpoints are configured and accessible."""
        pass

    @abstractmethod
    def _call_api(self, prompt: str, system_prompt: str) -> Optional[str]:
        """Low-level API call implementation to be provided by subclasses."""
        pass

    def generate(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """
        Secure, token-optimized wrapper for LLM completions.
        - Redacts all secrets from prompts prior to transmission
        - Truncates oversized contexts to enforce token budgets
        - Caches identical prompt hashes to avoid redundant token spend
        - Never crashes the caller on network or API failures
        """
        if not self.is_available():
            self.last_error = "Provider credentials are missing or invalid."
            return None

        # 1. Mandatory secret redaction before network transmission
        clean_prompt = SecretRedactor.redact(prompt)
        clean_system = SecretRedactor.redact(system_prompt)

        # 2. Token / size budget enforcement
        if len(clean_prompt) > MAX_PROMPT_CHARS:
            clean_prompt = clean_prompt[:MAX_PROMPT_CHARS] + "\n\n[Context truncated for token optimization]"

        # 3. Check memory cache for identical queries
        cache_key = hashlib.sha256(f"{self.name}::{clean_system}::{clean_prompt}".encode("utf-8")).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        # 4. Safe API call
        try:
            response = self._call_api(clean_prompt, clean_system)
            if response:
                # Sanitize response just in case
                sanitized_response = SecretRedactor.redact(response)
                self._cache[cache_key] = sanitized_response
                return sanitized_response
        except LLMProviderError as exc:
            # The engine can finish its static baseline, but callers can now
            # report the provider failure honestly instead of treating it as AI success.
            self.last_error = str(exc)
            return None
        except Exception:
            self.last_error = "Unexpected provider error."
            return None

        return None
