"""Cost/complexity-aware model routing (v1: deterministic rules).

Routes requests to the cheapest capable tier:
  - long/structured/code-heavy prompts -> premium tier
  - short/simple queries -> economy tier
Upgrade path documented in README: replace rules with a bandit trained on
eval outcomes. Routing decisions are audited for every request."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteTier:
    name: str
    model: str
    cost_per_1k_tokens: float


TIERS: dict[str, RouteTier] = {
    "economy": RouteTier("economy", "echo-economy", 0.0001),
    "premium": RouteTier("premium", "echo-premium", 0.0015),
}

# Real $/1k blended rates per model id (input+output avg, public pricing
# rounded). Tier defaults above stay as fallback; lookups prefer this table
# so per-call $ metrics track real provider cost, not echo placeholders.
MODEL_PRICES_USD_PER_1K: dict[str, float] = {
    "echo-economy": 0.0001,
    "echo-premium": 0.0015,
    "gpt-4o-mini": 0.00015,
    "gpt-4o": 0.0025,
    "o4-mini": 0.0011,
    "claude-3-5-haiku": 0.0008,
    "claude-sonnet-4": 0.003,
    "Qwen/Qwen3.8-27B": 0.0003,
    "deepseek-ai/DeepSeek-V4-Pro": 0.0006,
    "moonshotai/Kimi-K2": 0.0005,
}

_CODE_MARKERS = ("```", "def ", "class ", "import ", "SELECT ", "function")
_STRUCTURED_MARKERS = ("{", "[", "json", "schema", "table", "step by step")


def classify_complexity(messages: list[dict]) -> str:
    """Return 'premium' | 'economy'."""
    text = "\n".join(str(m.get("content", "")) for m in messages)
    length = len(text)
    if any(marker in text for marker in _CODE_MARKERS):
        return "premium"
    if any(marker in text.lower() for marker in _STRUCTURED_MARKERS) and length > 400:
        return "premium"
    if length > 2000:
        return "premium"
    return "economy"


def route(messages: list[dict], allowed: set[str] | None = None) -> tuple[RouteTier, str]:
    """Returns (tier, reason). `allowed` restricts tier names/models per tenant."""
    tier_name = classify_complexity(messages)
    tier = TIERS[tier_name]
    reason = f"rules: complexity={tier_name}, length={sum(len(str(m.get('content',''))) for m in messages)}"
    if allowed:
        key = tier.model if tier.model in allowed else tier_name if tier_name in allowed else None
        if key is None:
            # fall back to cheapest allowed tier (economy preferred)
            fallback = "economy" if ("economy" in allowed or "echo-economy" in allowed) else sorted(allowed)[0]
            if fallback in TIERS:
                tier = TIERS[fallback]
            elif fallback in MODEL_PRICES_USD_PER_1K:
                tier = RouteTier(fallback, fallback, MODEL_PRICES_USD_PER_1K[fallback])
            else:
                tier = TIERS["economy"]
            reason += f", allowlist enforced: {tier.name} (wanted {tier_name})"
        else:
            reason += ", allowlist ok"
    return tier, reason


def price_for(model: str, fallback: float) -> float:
    return MODEL_PRICES_USD_PER_1K.get(model, fallback)


def estimate_cost_usd(tier: RouteTier, input_tokens: int, output_tokens: int) -> float:
    """Cost-per-prediction estimate from tier rates (cache hits cost 0)."""
    rate = price_for(tier.model, tier.cost_per_1k_tokens)
    return round((input_tokens + output_tokens) / 1000 * rate, 6)
