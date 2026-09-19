"""Pluggable embeddings for RAG: hash fallback + API providers.

Default path is legacy (hashed n-gram vectors inside retriever) — zero deps,
deterministic, CI-safe. Set AEGIS_EMBED_PROVIDER=hash|gmi|openai for real
vectors; the retriever prefers real cosine when vectors exist and falls back
to legacy otherwise. Postgres stores the JSON embedding per chunk so restarts
keep the vector index without re-calling the API.
"""

import hashlib
import math
import os


def l2norm(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in vec))
    return [x / n for x in vec] if n else vec


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class HashEmbedProvider:
    """Deterministic no-dep embedding: token-hash buckets, L2-normalized."""

    name = "hash"

    def __init__(self, dims: int = 128) -> None:
        self.dims = dims

    def embed(self, texts: list[str]) -> list[list[float]]:
        from aegis.rag.retriever import tokenize

        out = []
        for text in texts:
            vec = [0.0] * self.dims
            for tok in tokenize(text):
                idx = int(hashlib.sha256(tok.encode()).hexdigest()[:16], 16) % self.dims
                vec[idx] += 1.0
            out.append(l2norm(vec))
        return out


class GMIEmbedProvider:
    name = "gmi"

    def __init__(self, model: str = "", api_key: str = "", base_url: str = "") -> None:
        self.model = model or os.environ.get("GMI_EMBED_MODEL", "Qwen/Qwen3-Embedding-8B")
        self.api_key = api_key or os.environ.get("GMI_API_KEY", "")
        base = (base_url or os.environ.get("GMI_BASE_URL",
                "https://api.gmi-serving.com/v1")).rstrip("/")
        self.api_url = f"{base}/embeddings"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def embed(self, texts: list[str]) -> list[list[float]]:
        import httpx

        if not self.available:
            raise RuntimeError("GMI_API_KEY not set")
        resp = httpx.post(self.api_url,
                          json={"model": self.model, "input": texts},
                          headers={"Authorization": f"Bearer {self.api_key}"},
                          timeout=30.0)
        resp.raise_for_status()
        items = sorted(resp.json()["data"], key=lambda d: d["index"])
        return [l2norm(d["embedding"]) for d in items]

    async def aembed(self, texts: list[str]) -> list[list[float]]:
        """Async variant: sync httpx.post would block the event loop (M6)."""
        import httpx

        if not self.available:
            raise RuntimeError("GMI_API_KEY not set")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self.api_url,
                                     json={"model": self.model, "input": texts},
                                     headers={"Authorization": f"Bearer {self.api_key}"})
            resp.raise_for_status()
            items = sorted(resp.json()["data"], key=lambda d: d["index"])
            return [l2norm(d["embedding"]) for d in items]


class OpenAIEmbedProvider:
    name = "openai"

    def __init__(self, model: str = "") -> None:
        self.model = model or os.environ.get("OPENAI_EMBED_MODEL", "text-embedding-3-small")
        self.api_key = os.environ.get("OPENAI_API_KEY", "")

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def embed(self, texts: list[str]) -> list[list[float]]:
        import httpx

        if not self.available:
            raise RuntimeError("OPENAI_API_KEY not set")
        resp = httpx.post("https://api.openai.com/v1/embeddings",
                          json={"model": self.model, "input": texts},
                          headers={"Authorization": f"Bearer {self.api_key}"},
                          timeout=30.0)
        resp.raise_for_status()
        items = sorted(resp.json()["data"], key=lambda d: d["index"])
        return [l2norm(d["embedding"]) for d in items]

    async def aembed(self, texts: list[str]) -> list[list[float]]:
        """Async variant: sync httpx.post would block the event loop (M6)."""
        import httpx

        if not self.available:
            raise RuntimeError("OPENAI_API_KEY not set")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post("https://api.openai.com/v1/embeddings",
                                     json={"model": self.model, "input": texts},
                                     headers={"Authorization": f"Bearer {self.api_key}"})
            resp.raise_for_status()
            items = sorted(resp.json()["data"], key=lambda d: d["index"])
            return [l2norm(d["embedding"]) for d in items]


def get_embed_provider(name: str = "", model: str = ""):
    """Factory from env/config. 'legacy'/'' -> None (old hash_vec path)."""
    kind = (name or os.environ.get("AEGIS_EMBED_PROVIDER", "legacy")).lower()
    if kind in ("", "legacy", "none"):
        return None
    if kind == "hash":
        return HashEmbedProvider()
    if kind == "gmi":
        return GMIEmbedProvider(model=model)
    if kind == "openai":
        return OpenAIEmbedProvider(model=model)
    raise ValueError(f"unknown embed provider: {kind}")
