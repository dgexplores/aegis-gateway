"""Provider registry with failover chains and circuit breakers."""

from aegis.breaker import BreakerOpen, CircuitBreaker
from aegis.config import Settings
from aegis.providers.anthropic_provider import AnthropicProvider
from aegis.providers.base import BaseProvider, Completion, ProviderError
from aegis.providers.echo import EchoProvider
from aegis.providers.gmi_provider import GMIProvider
from aegis.providers.openai_provider import OpenAIProvider


class AllProvidersDown(Exception):
    pass


def build_registry(settings: Settings) -> dict[str, tuple[BaseProvider, CircuitBreaker]]:
    """Returns ordered failover chain: configured providers, echo always last."""
    wanted = [p.strip().lower() for p in settings.providers.split(",") if p.strip()]
    chain: list[BaseProvider] = []
    for name in wanted:
        if name == "openai" and OpenAIProvider().available:
            chain.append(OpenAIProvider())
        elif name == "anthropic" and AnthropicProvider().available:
            chain.append(AnthropicProvider())
        elif name == "gmi" and GMIProvider().available:
            chain.append(GMIProvider())
    chain.append(EchoProvider())  # deterministic fallback — keeps platform usable

    registry: dict[str, tuple[BaseProvider, CircuitBreaker]] = {}
    for provider in chain:
        breaker = CircuitBreaker(provider.name)
        registry[provider.name] = (provider, breaker)
    return registry


async def complete_with_failover(
    registry: dict[str, tuple[BaseProvider, CircuitBreaker]],
    messages: list[dict],
    model: str,
    max_tokens: int,
    preferred: str | None = None,
) -> tuple[Completion, str]:
    """Try preferred/first providers in order; skip open circuits; echo guarantees liveness."""
    names = list(registry.keys())
    if preferred in registry and preferred != "echo":
        names.remove(preferred)
        names.insert(0, preferred)

    errors: list[str] = []
    for name in names:
        provider, breaker = registry[name]
        if name != "echo" and not getattr(provider, "available", True):
            continue
        try:
            breaker.before_call()
        except BreakerOpen:
            errors.append(f"{name}: circuit open")
            continue
        try:
            completion = await provider.complete(messages, model, max_tokens)
            breaker.record_success()
            return completion, name
        except ProviderError as exc:
            breaker.record_failure()
            errors.append(f"{name}: {exc}")
    raise AllProvidersDown("; ".join(errors) or "no providers configured")
