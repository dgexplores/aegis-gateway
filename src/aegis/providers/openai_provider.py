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

    async def astream(self, messages: list[dict], model: str, max_tokens: int):  # type: ignore[no-untyped-def]
        if not self.available:
            raise ProviderError("OPENAI_API_KEY not set")
        payload = {
            "model": model if model.startswith(("gpt", "o")) else "gpt-4o-mini",
            "messages": messages,
            "max_tokens": max_tokens,
            "user": "aegis-gateway",
            "stream": True,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                async with client.stream("POST", API_URL, json=payload,
                                         headers=headers) as resp:
                    if resp.status_code != 200:
                        raise ProviderError(f"openai http {resp.status_code}")
                    if "text/event-stream" not in resp.headers.get("content-type", ""):
                        raise ProviderError("openai non-stream response")
                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            return
                        try:
                            import json as _json
                            obj = _json.loads(data)
                            delta = obj["choices"][0].get("delta", {}).get("content", "")
                            if delta:
                                yield delta
                        except (ValueError, KeyError):  # noqa: S112 — skip malformed SSE line
                            continue
        except ProviderError:
            completion = await self.complete(messages, model, max_tokens)
            words = completion.text.split(" ")
            for i, w in enumerate(words):
                yield w + (" " if i < len(words) - 1 else "")
