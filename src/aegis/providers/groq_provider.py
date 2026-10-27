"""Groq's OpenAI-compatible API, with explicit provider identity and timeouts."""

import os
import time

import httpx

from aegis.providers.base import BaseProvider, Completion, ProviderError, extract_openai_text


class GroqProvider(BaseProvider):
    name = "groq"

    def __init__(self, api_key: str = "", default_model: str = "llama-3.3-70b-versatile") -> None:
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.default_model = default_model

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion:
        if not self.available:
            raise ProviderError("GROQ_API_KEY not set")
        chosen = self.default_model if model.startswith("echo-") else model
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=25.0) as client:
                response = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": chosen, "messages": messages, "max_tokens": max_tokens, "temperature": 0},
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            # Never include response bodies or request headers in errors.
            status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else "transport"
            raise ProviderError(f"groq unavailable: {status}") from exc
        data = response.json()
        usage = data.get("usage", {})
        text = extract_openai_text(data, self.name)
        if not text.strip():
            raise ProviderError("groq returned empty assistant content")
        return Completion(
            text=text,
            model=data.get("model", chosen),
            provider=self.name,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )
