"""Redis-backed budgets: shared counters + memory fallback on flap."""

import pytest

from aegis.budget import BudgetExceeded, TokenBudget


class FakeRedis:
    def __init__(self, fail=False):
        self.data: dict[str, int] = {}
        self.fail = fail

    def _guard(self):
        if self.fail:
            raise ConnectionError("redis down")

    def get(self, key):
        self._guard()
        value = self.data.get(key)
        return None if value is None else str(value)

    def incrby(self, key, amount):
        self._guard()
        self.data[key] = int(self.data.get(key, 0)) + amount
        return self.data[key]

    def expire(self, key, ttl):
        self._guard()
        return True


def test_shared_counter_blocks_at_cap():
    budget = TokenBudget(100, redis_client=FakeRedis())
    budget.record("acme", 60)
    budget.preflight("acme", 30)  # 90 <= 100 ok
    with pytest.raises(BudgetExceeded):
        budget.preflight("acme", 41)  # 101 > 100
    assert budget.usage("acme")["used"] == 60


def test_two_instances_agree_via_shared_redis():
    shared = FakeRedis()
    first = TokenBudget(100, redis_client=shared)
    second = TokenBudget(100, redis_client=shared)
    first.record("acme", 70)
    assert second.usage("acme")["used"] == 70
    with pytest.raises(BudgetExceeded):
        second.preflight("acme", 31)


def test_redis_flap_falls_back_to_memory():
    budget = TokenBudget(50, redis_client=FakeRedis(fail=True))
    budget.record("acme", 20)
    budget.preflight("acme", 10)
    assert budget.usage("acme")["used"] == 20
    with pytest.raises(BudgetExceeded):
        budget.preflight("acme", 31)
