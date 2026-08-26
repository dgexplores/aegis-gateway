"""Anthropic provider (httpx). Only active when key configured."""

import os
import time

import httpx

from aegis.providers.base import BaseProvider, Completion, ProviderError

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
TIMEOUT = 30.0


class AnthropicProvider(BaseProvider):
    name = "anthropic"

    def __init__(self) -> None:
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion:
        if not self.available:
            raise ProviderError("ANTHROPIC_API_KEY not set")
        start = time.perf_counter()

        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [{"role": m["role"], "content": m["content"]}
                 for m in messages if m["role"] in ("user", "assistant")]

        payload = {
            "model": model if model.startswith("claude") else "claude-3-5-haiku-latest",
            "max_tokens": max_tokens,
            "messages": convo,
        }
        if system:
            payload["system"] = system
        headers = {"x-api-key": self.api_key, "anthropic-version": API_VERSION}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(API_URL, json=payload, headers=headers)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"anthropic http {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"anthropic transport error: {exc}") from exc

        data = resp.json()
        latency = (time.perf_counter() - start) * 1000
        text = "".join(block.get("text", "") for block in data.get("content", []))
        usage = data.get("usage", {})
        return Completion(
            text=text,
            model=data.get("model", model),
            provider=self.name,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=round(latency, 2),
            raw={"stop_reason": data.get("stop_reason")},
        )
