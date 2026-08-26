"""OpenAI provider (httpx, no SDK lock-in). Only active when key configured."""

import os
import time

import httpx

from aegis.providers.base import BaseProvider, Completion, ProviderError

API_URL = "https://api.openai.com/v1/chat/completions"
TIMEOUT = 30.0


class OpenAIProvider(BaseProvider):
    name = "openai"

    def __init__(self) -> None:
        self.api_key = os.environ.get("OPENAI_API_KEY", "")

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion:
        if not self.available:
            raise ProviderError("OPENAI_API_KEY not set")
        start = time.perf_counter()
        payload = {
            "model": model if model.startswith(("gpt", "o")) else "gpt-4o-mini",
            "messages": messages,
            "max_tokens": max_tokens,
            "user": "aegis-gateway",  # never forward tenant identity
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(API_URL, json=payload, headers=headers)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"openai http {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"openai transport error: {exc}") from exc

        data = resp.json()
        usage = data.get("usage", {})
        latency = (time.perf_counter() - start) * 1000
        return Completion(
            text=data["choices"][0]["message"]["content"],
            model=data.get("model", model),
            provider=self.name,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=round(latency, 2),
            raw={"finish_reason": data["choices"][0].get("finish_reason")},
        )
