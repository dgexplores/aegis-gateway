import httpx
import pytest

from aegis.config import Settings
from aegis.providers.base import ProviderError
from aegis.providers.groq_provider import GroqProvider
from aegis.providers.registry import build_registry, complete_with_failover


@pytest.mark.asyncio
async def test_groq_uses_safe_messages_and_reports_usage(monkeypatch):
    async def post(client, url, **kwargs):
        assert url == "https://api.groq.com/openai/v1/chat/completions"
        assert kwargs["json"]["model"] == "llama-3.3-70b-versatile"
        assert kwargs["json"]["max_tokens"] == 128
        assert kwargs["json"]["messages"] == [{"role": "user", "content": "[EMAIL_1]"}]
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "model": "llama-3.3-70b-versatile",
                "choices": [{"message": {"content": "Policy answer"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8},
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    result = await GroqProvider("test-only-key").complete(
        [{"role": "user", "content": "[EMAIL_1]"}], "echo-economy", 128
    )
    assert result.provider == "groq" and result.input_tokens == 12 and result.output_tokens == 8


@pytest.mark.asyncio
async def test_upstream_failure_falls_back_without_exposing_secret(monkeypatch):
    async def post(client, url, **kwargs):
        return httpx.Response(429, request=httpx.Request("POST", url), text="sensitive-provider-body")

    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    with pytest.raises(ProviderError, match="groq unavailable: 429") as caught:
        await GroqProvider("test-only-key").complete([], "echo-economy", 128)
    assert "sensitive" not in str(caught.value)
    registry = build_registry(Settings(groq_api_key="test-only-key", providers="groq"))
    completion, provider = await complete_with_failover(
        registry, [{"role": "user", "content": "hello"}], "echo-economy", 128
    )
    assert provider == "echo" and completion.text


def test_unconfigured_groq_is_not_registered(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert list(build_registry(Settings(providers="groq", groq_api_key=""))) == ["echo"]


@pytest.mark.asyncio
async def test_gemini_identity_endpoint_and_key_isolation(monkeypatch):
    from aegis.providers.gemini_provider import GeminiProvider

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "unrelated-groq-key")
    assert not GeminiProvider().available

    async def post(client, url, **kwargs):
        assert url == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        assert kwargs["json"]["model"] == "gemini-2.5-flash"
        assert kwargs["json"]["reasoning_effort"] == "none"
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "choices": [{"message": {"content": "Grounded policy answer"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    registry = build_registry(Settings(providers="gemini", gemini_api_key="test-only-key"))
    result, name = await complete_with_failover(registry, [], "echo-economy", 128)
    assert name == result.provider == "gemini"
