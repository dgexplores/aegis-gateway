import asyncio

from aegis.config import Settings
from aegis.gateway import build_gateway
from aegis.router import MODEL_PRICES_USD_PER_1K, TIERS, estimate_cost_usd, route


def test_real_prices_table_has_known_models():
    assert MODEL_PRICES_USD_PER_1K["gpt-4o-mini"] < MODEL_PRICES_USD_PER_1K["gpt-4o"]
    assert MODEL_PRICES_USD_PER_1K["echo-economy"] == TIERS["economy"].cost_per_1k_tokens


def test_estimate_uses_real_table():
    tier = TIERS["economy"]
    assert estimate_cost_usd(tier, 1000, 0) == round(MODEL_PRICES_USD_PER_1K["echo-economy"], 6)


def test_allowlist_ok_keeps_tier():
    tier, reason = route([{"role": "user", "content": "hi"}], allowed={"echo-economy"})
    assert tier.name == "economy"
    assert "allowlist ok" in reason


def test_allowlist_forces_fallback():
    long_code = "```\n" + "x" * 3000
    tier, reason = route([{"role": "user", "content": long_code}], allowed={"echo-economy"})
    assert tier.name == "economy"
    assert "allowlist enforced" in reason


def test_config_parses_tenant_models():
    s = Settings(tenant_models="acme:echo-economy+gpt-4o-mini;other:echo-premium")
    allow = s.model_allowlist()
    assert allow["acme"] == {"echo-economy", "gpt-4o-mini"}
    assert allow["other"] == {"echo-premium"}


def test_gateway_enforces_allowlist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = Settings(
        env="test",
        tenants="d:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:chat",
        providers="echo",
        tenant_models="d:echo-economy",
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
    )
    gw = asyncio.run(build_gateway(s))
    long_code = "```\n" + "x" * 3000
    res = asyncio.run(gw.handle_chat("d", [{"role": "user", "content": long_code}],
                                     use_cache=False))
    assert res["routing"]["tier"] == "economy"
    assert "allowlist enforced" in res["routing"]["reason"]
