"""LLM provider abstraction. Every provider implements the same async contract;
the gateway treats them interchangeably behind circuit breakers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Completion:
    text: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    raw: dict = field(default_factory=dict)


class ProviderError(Exception):
    pass


class BaseProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion:
        ...

    async def astream(self, messages: list[dict], model: str, max_tokens: int):  # type: ignore[no-untyped-def]
        """Yield text deltas word-by-word. Providers override with true SSE."""
        completion = await self.complete(messages, model, max_tokens)
        words = completion.text.split(" ")
        for i, w in enumerate(words):
            yield w + (" " if i < len(words) - 1 else "")
