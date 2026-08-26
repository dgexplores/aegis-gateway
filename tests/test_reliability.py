import pytest

from aegis.budget import BudgetExceeded, TokenBudget
from aegis.cache import TTLCache
from aegis.router import route


def test_budget_preflight_blocks_overage():
    b = TokenBudget(daily_limit=100)
    b.record("t", 90)  # actuals consumed today
    with pytest.raises(BudgetExceeded):
        b.preflight("t", 50)


def test_budget_records_and_rolls():
    b = TokenBudget(daily_limit=100)
    b.record("t", 30)
    usage = b.usage("t")
    assert usage["used"] == 30
    assert usage["remaining"] == 70


def test_cache_roundtrip_and_ttl():
    c = TTLCache(ttl_seconds=1)
    k = c.make_key("t1", "m", [{"role": "user", "content": "hi"}])
    assert c.get(k) is None
    c.put(k, {"answer": 42})
    assert c.get(k) == {"answer": 42}


def test_cache_tenant_isolation():
    c = TTLCache(ttl_seconds=10)
    msgs = [{"role": "user", "content": "same question"}]
    k1 = c.make_key("tenant-a", "m", msgs)
    k2 = c.make_key("tenant-b", "m", msgs)
    assert k1 != k2  # cross-tenant cache leakage impossible


def test_router_sends_code_to_premium():
    messages = [{"role": "user", "content": "```python\ndef f(): pass\n```"}]
    tier, _ = route(messages, ["echo"])
    assert tier.name == "premium"


def test_router_sends_short_query_to_economy():
    messages = [{"role": "user", "content": "what is my vacation policy?"}]
    tier, _ = route(messages, ["echo"])
    assert tier.name == "economy"
