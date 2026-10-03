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


def extract_openai_text(data: dict, provider: str) -> str:
    """Pull the assistant text out of an OpenAI-compatible chat completion.

    A hard `data["choices"][0]["message"]["content"]` reads as safe and is not.
    A reasoning model that spends its whole output budget thinking returns
    **HTTP 200 with no `content` key at all**, and indexing that raised KeyError
    — a 500 to the caller, from a request the provider considered successful.
    Against Gemini 3.8 that is the ordinary response for a tight `max_tokens`,
    which is why the echo-backed test suite could never have found it: the mock
    always answers, so the field is always there.

    Also handles the two other shapes seen in the wild: `content` as a list of
    parts, and the answer living under `text` instead.
    """
    choices = data.get("choices") or [{}]
    choice = choices[0] or {}
    message = choice.get("message") or {}

    content = message.get("content", None)
    if content is None:
        content = choice.get("text", None)

    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))

    if content is None:
        # No visible text. When the provider stopped because it ran out of
        # output budget, that *is* the diagnosis — a thinking model spends
        # max_tokens on reasoning before it writes anything. Keyed off
        # finish_reason rather than a reasoning field, because most
        # OpenAI-compatible layers do not echo the reasoning back: Gemini puts
        # it in a provider-specific `extra_content` blob, so gating the hint on
        # the absence of a field that is usually absent would leave the caller
        # with the least useful message exactly when they need it.
        reasoning = message.get("reasoning_content")
        if choice.get("finish_reason") == "length":
            detail = " — the output budget ran out before any text was produced; raise max_tokens"
        elif reasoning:
            detail = " — the model appears to have reasoned without emitting text; raise max_tokens"
        else:
            detail = ""
        raise ProviderError(
            f"{provider}: response had no assistant content (finish_reason={choice.get('finish_reason')!r}){detail}"
        )

    return str(content)


class BaseProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion: ...

    async def astream(self, messages: list[dict], model: str, max_tokens: int):  # type: ignore[no-untyped-def]
        """Yield text deltas word-by-word. Providers override with true SSE."""
        completion = await self.complete(messages, model, max_tokens)
        words = completion.text.split(" ")
        for i, w in enumerate(words):
            yield w + (" " if i < len(words) - 1 else "")
