"""GMI Cloud provider — OpenAI-compatible. https://api.gmi-serving.com/v1"""

import os
import time

import httpx

from aegis.providers.base import BaseProvider, Completion, ProviderError

DEFAULT_BASE = "https://api.gmi-serving.com/v1"
TIMEOUT = 30.0


class GMIProvider(BaseProvider):
    name = "gmi"

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        # Accept explicit key (from Settings) or fall back to either env var name
        self.api_key = (
            api_key
            or os.environ.get("GMI_API_KEY", "")
            or os.environ.get("AEGIS_GMI_API_KEY", "")
        )
        base = (
            base_url
            or os.environ.get("GMI_BASE_URL", "")
            or os.environ.get("AEGIS_GMI_BASE_URL", "")
            or DEFAULT_BASE
        ).rstrip("/")
        self.api_url = f"{base}/chat/completions"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion:
        if not self.available:
            raise ProviderError("GMI_API_KEY not set")
        start = time.perf_counter()
        # GMI expects model ids like Qwen/Qwen3.8-27B, deepseek-ai/DeepSeek-V4-Pro etc.
        # If caller passes echo-* tier names, map to a sensible default.
        if model.startswith("echo-"):
            model = os.environ.get("GMI_MODEL", "Qwen/Qwen3.8-27B")
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "user": "aegis-gateway",
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(self.api_url, json=payload, headers=headers)
                if resp.status_code == 402:
                    raise ProviderError("gmi insufficient balance — add credits at console.gmicloud.ai")
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"gmi http {exc.response.status_code}: {exc.response.text[:200]}") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"gmi transport error: {exc}") from exc

        data = resp.json()
        choice = data["choices"][0]
        # OpenAI-compatible: content may be string or structured
        content = choice["message"]["content"] if "message" in choice else choice.get("text", "")
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content)
        usage = data.get("usage", {})
        latency = (time.perf_counter() - start) * 1000
        return Completion(
            text=str(content),
            model=data.get("model", model),
            provider=self.name,
            input_tokens=usage.get("prompt_tokens", usage.get("input_tokens", 0)),
            output_tokens=usage.get("completion_tokens", usage.get("output_tokens", 0)),
            latency_ms=round(latency, 2),
            raw={"finish_reason": choice.get("finish_reason")},
        )

    async def list_models(self) -> list[dict]:
        """Helper for debugging: GET /v1/models on the GMI endpoint."""
        base = os.environ.get("GMI_BASE_URL", DEFAULT_BASE).rstrip("/")
        url = f"{base}/models"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json().get("data", [])
