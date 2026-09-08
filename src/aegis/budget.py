"""Per-tenant daily token budgets. Enforced pre-request (estimate) and
post-response (actuals). Prevents runaway-cost / resource-exhaustion abuse
(OWASP LLM10: Unbounded Consumption)."""

import time
from collections import defaultdict


class BudgetExceeded(Exception):
    pass


class TokenBudget:
    """Daily token budgets, shared via Redis when configured.

    redis_client set -> counters live in `budget:{tenant}:{day}` (INCRBY,
    2-day TTL) so all replicas agree. Unset or unreachable -> in-process
    memory fallback so dev/tests run dependency-free. A Redis flap may
    under-count that window; preflight stays fail-closed on known usage.
    """

    def __init__(self, daily_limit: int, redis_client=None) -> None:
        self.daily_limit = daily_limit
        self.redis = redis_client
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

    def _rkey(self, tenant: str) -> str:
        return f"budget:{tenant}:{self._today()}"

    def _rused(self, tenant: str) -> int | None:
        """Shared counter or None when Redis is absent/unreachable."""
        if self.redis is None:
            return None
        try:
            value = self.redis.get(self._rkey(tenant))
            return int(value) if value is not None else 0
        except Exception:  # noqa: BLE001 — degrade to memory for this call
            return None

    def preflight(self, tenant: str, estimated_tokens: int) -> None:
        used = self._rused(tenant)
        if used is not None:
            if used + estimated_tokens > self.daily_limit:
                raise BudgetExceeded(
                    f"daily token budget exceeded for '{tenant}' "
                    f"(used={used}, est={estimated_tokens}, cap={self.daily_limit})"
                )
            return
        self._roll_day(tenant)
        if self._used[tenant] + estimated_tokens > self.daily_limit:
            raise BudgetExceeded(
                f"daily token budget exceeded for '{tenant}' "
                f"(used={self._used[tenant]}, est={estimated_tokens}, cap={self.daily_limit})"
            )

    def record(self, tenant: str, tokens: int) -> None:
        if self._try_redis_record(tenant, tokens):
            return
        self._roll_day(tenant)
        self._used[tenant] += tokens

    def _try_redis_record(self, tenant: str, tokens: int) -> bool:
        if self.redis is None:
            return False
        try:
            self.redis.incrby(self._rkey(tenant), tokens)
            self.redis.expire(self._rkey(tenant), 172_800)
            return True
        except Exception:  # noqa: BLE001 — degrade to memory for this call
            return False

    def usage(self, tenant: str) -> dict:
        used = self._rused(tenant)
        if used is None:
            self._roll_day(tenant)
            used = self._used[tenant]
        return {
            "tenant": tenant,
            "used": used,
            "limit": self.daily_limit,
            "remaining": max(0, self.daily_limit - used),
            "day": self._today(),
        }
