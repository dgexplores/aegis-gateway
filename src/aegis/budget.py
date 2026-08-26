"""Per-tenant daily token budgets. Enforced pre-request (estimate) and
post-response (actuals). Prevents runaway-cost / resource-exhaustion abuse
(OWASP LLM10: Unbounded Consumption)."""

import time
from collections import defaultdict


class BudgetExceeded(Exception):
    pass


class TokenBudget:
    def __init__(self, daily_limit: int) -> None:
        self.daily_limit = daily_limit
        self._used: dict[str, int] = defaultdict(int)
        self._day: dict[str, str] = {}

    @staticmethod
    def _today() -> str:
        return time.strftime("%Y-%m-%d")

    def _roll_day(self, tenant: str) -> None:
        today = self._today()
        if self._day.get(tenant) != today:
            self._day[tenant] = today
            self._used[tenant] = 0

    def estimate_tokens(self, text: str) -> int:
        # ~4 chars/token heuristic; good enough for pre-flight gating.
        return max(1, len(text) // 4)

    def preflight(self, tenant: str, estimated_tokens: int) -> None:
        self._roll_day(tenant)
        if self._used[tenant] + estimated_tokens > self.daily_limit:
            raise BudgetExceeded(
                f"daily token budget exceeded for '{tenant}' "
                f"(used={self._used[tenant]}, est={estimated_tokens}, cap={self.daily_limit})"
            )

    def record(self, tenant: str, tokens: int) -> None:
        self._roll_day(tenant)
        self._used[tenant] += tokens

    def usage(self, tenant: str) -> dict:
        self._roll_day(tenant)
        used = self._used[tenant]
        return {
            "tenant": tenant,
            "used": used,
            "limit": self.daily_limit,
            "remaining": max(0, self.daily_limit - used),
            "day": self._today(),
        }
