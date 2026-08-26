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


def route(messages: list[dict], allowed_providers: list[str]) -> tuple[RouteTier, str]:
    """Returns (tier, reason). Only routes to providers the tenant may use."""
    tier_name = classify_complexity(messages)
    tier = TIERS[tier_name]
    reason = f"rules: complexity={tier_name}, length={sum(len(str(m.get('content',''))) for m in messages)}"
    return tier, reason
