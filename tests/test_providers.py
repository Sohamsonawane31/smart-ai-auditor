"""Tests for the supported offline, NVIDIA, and OpenCode Zen provider surface."""

import pytest
import requests

from ai_project_auditor.providers import NVIDIAProvider, OpenCodeProvider, get_provider
from ai_project_auditor.providers.base import LLMProvider, MAX_PROMPT_CHARS


def test_provider_factory():
    assert get_provider("offline") is None
    assert isinstance(get_provider("nvidia"), NVIDIAProvider)
    assert isinstance(get_provider("opencode"), OpenCodeProvider)
    with pytest.raises(ValueError):
        get_provider("local")


def test_nvidia_uses_documented_nim_base_url_and_model():
    provider = NVIDIAProvider(api_key="test-key")
    assert provider.base_url == "https://integrate.api.nvidia.com/v1"
    assert provider.model == "meta/llama-3.3-70b-instruct"


def test_opencode_uses_zen_chat_completions_base_url():
    provider = OpenCodeProvider(api_key="test-key")
    assert provider.base_url == "https://opencode.ai/zen/v1"
    assert provider.model == "kimi-k2.7-code"


def test_provider_redacts_and_limits_prompts():
    class CaptureProvider(LLMProvider):
        @property
        def name(self): return "capture"
        def is_available(self): return True
        def _call_api(self, prompt, system_prompt):
            self.prompt = prompt
            return "OK"

    provider = CaptureProvider()
    provider.generate("sk-ant-api03-abcdef1234567890abcdef1234567890")
    assert "sk-ant-" not in provider.prompt

    provider = CaptureProvider()
    provider.generate("A" * (MAX_PROMPT_CHARS + 50))
    assert "[Context truncated" in provider.prompt


def test_unconfigured_remote_providers_fail_gracefully():
    for provider in (NVIDIAProvider(api_key=""), OpenCodeProvider(api_key="")):
        assert provider.is_available() is False
        assert provider.generate("Hello") is None
        assert "credentials" in provider.last_error.lower()


class _Response:
    def __init__(self, status_code=200, payload=None, json_error=None):
        self.status_code = status_code
        self.payload = payload
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


@pytest.mark.parametrize("provider_type, expected_url", [
    (NVIDIAProvider, "https://integrate.api.nvidia.com/v1/chat/completions"),
    (OpenCodeProvider, "https://opencode.ai/zen/v1/chat/completions"),
])
def test_remote_providers_submit_openai_compatible_chat_requests(monkeypatch, provider_type, expected_url):
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return _Response(payload={"choices": [{"message": {"content": "CONFIRMED: No"}}]})

    monkeypatch.setattr("requests.post", fake_post)
    provider = provider_type(api_key="test-key")
    assert provider.generate("audit this", "system instruction") == "CONFIRMED: No"
    assert captured["url"] == expected_url
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["json"]["model"] == provider.model
    assert captured["json"]["messages"][0]["role"] == "system"
    assert captured["timeout"] == 30
    assert provider.last_error is None


@pytest.mark.parametrize("provider_type", [NVIDIAProvider, OpenCodeProvider])
@pytest.mark.parametrize("response, expected", [
    (_Response(payload={}), "malformed"),
    (_Response(status_code=401, payload={}), "authentication failed"),
    (_Response(status_code=429, payload={}), "rate limit"),
])
def test_remote_provider_errors_are_actionable(monkeypatch, provider_type, response, expected):
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: response)
    provider = provider_type(api_key="test-key")
    assert provider.generate("audit this") is None
    assert expected in provider.last_error.lower()


@pytest.mark.parametrize("provider_type", [NVIDIAProvider, OpenCodeProvider])
def test_remote_provider_timeout_is_actionable(monkeypatch, provider_type):
    def timeout(*_args, **_kwargs):
        raise requests.Timeout("slow")

    monkeypatch.setattr("requests.post", timeout)
    provider = provider_type(api_key="test-key")
    assert provider.generate("audit this") is None
    assert "timed out" in provider.last_error.lower()
