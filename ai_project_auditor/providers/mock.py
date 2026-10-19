"""
Mock LLM Provider for AI Project Auditor V2 tests and offline simulation.
"""

from typing import Optional, Dict
from .base import LLMProvider


class MockProvider(LLMProvider):
    """Deterministic mock provider returning synthesized security/code advice."""

    def __init__(self, responses: Optional[Dict[str, str]] = None):
        super().__init__(model="mock-auditor-v2")
        self.responses = responses or {}
        self.call_count = 0

    @property
    def name(self) -> str:
        return "MockAuditorProvider"

    def is_available(self) -> bool:
        return True

    def _call_api(self, prompt: str, system_prompt: str) -> Optional[str]:
        self.call_count += 1
        for key, resp in self.responses.items():
            if key in prompt:
                return resp

        # Default mock response
        return (
            "MOCK_ANALYSIS:\n"
            "- Finding: Architecture Review Note\n"
            "- Risk: Medium\n"
            "- Recommendation: Follow defensive coding patterns and enforce input sanitization."
        )
