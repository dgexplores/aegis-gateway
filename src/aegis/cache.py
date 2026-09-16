"""TTL response cache. Exact-match on (tenant, model, messages) hash.
Optional semantic layer hooks in later; v1 keeps it deterministic and safe:
cache keys are tenant-scoped so cross-tenant leakage is impossible."""

import hashlib
import json
import time
from typing import Any


class TTLCache:
    def __init__(self, ttl_seconds: int, max_entries: int = 10_000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._store: dict[str, tuple[float, Any]] = {}
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(tenant: str, model: str, messages: list[dict], max_tokens: int) -> str:
        """Cache key. `max_tokens` is part of the key on purpose.

        It is a required positional argument, not a defaulted one: omitting it
        meant a `max_tokens=10` request could be served a cached 4,000-token
        answer (and vice versa), because the answer length depends on it."""
        material = json.dumps({"t": tenant, "m": model, "msgs": messages,
                               "mt": max_tokens},
                              sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(material.encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            self.misses += 1
            return None
        ts, value = entry
        if time.time() - ts > self.ttl:
            del self._store[key]
            self.misses += 1
            return None
        self.hits += 1
        return value

    def put(self, key: str, value: Any) -> None:
        if len(self._store) >= self.max_entries:
            # drop oldest ~10% — cheap defense against unbounded memory
            cutoff = sorted(self._store.items(), key=lambda kv: kv[1][0])[: self.max_entries // 10]
            for k, _ in cutoff:
                del self._store[k]
        self._store[key] = (time.time(), value)

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "entries": len(self._store),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
        }
