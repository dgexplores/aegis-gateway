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
