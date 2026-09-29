"""One key must not identify two tenants.

The bug this pins: `Authenticator` keyed its lookup by key hash, so two tenants
configured with the same hash meant the second `dict` assignment silently
overwrote the first. No error, no log line — one tenant simply stopped existing,
and whoever held that key was served as the *other* tenant, with its scopes and
its documents. The kind of bug that surfaces as a support ticket weeks later
("customer A can see customer B's data") with nothing in the logs to explain it.

Both halves are covered: the config reports it as a boot problem, and the
authenticator refuses to start on it in *every* environment, not just production.
A cross-tenant hole is not something to gate on a deployment mode.
"""

import hashlib

import pytest

from aegis.config import Settings
from aegis.security.auth import AmbiguousTenantKey, Authenticator

ACME_KEY = "sk-acme-key-111111"
GLOBEX_KEY = "sk-globex-key-222222"


def _settings(tenants: str) -> Settings:
    return Settings(
        env="test",
        tenants=tenants,
        providers="echo",
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
    )


def _entry(tid: str, raw_key: str, scopes: str) -> str:
    return f"{tid}:{hashlib.sha256(raw_key.encode()).hexdigest()}:{scopes}"


def test_distinct_keys_are_fine():
    a = Authenticator(_settings(
        f"{_entry('acme', ACME_KEY, 'chat+rag')},{_entry('globex', GLOBEX_KEY, 'chat')}"
    ))
    assert len(a._by_key_hash) == 2


def test_one_key_two_tenants_is_refused():
    """The whole point: this used to silently keep whichever tenant was last."""
    with pytest.raises(AmbiguousTenantKey) as exc:
        Authenticator(_settings(
            f"{_entry('acme', ACME_KEY, 'chat+rag')},{_entry('globex', ACME_KEY, 'chat')}"
        ))
    message = str(exc.value)
    assert "acme" in message and "globex" in message, "the operator must be told which two"
    assert "gen_tenant.py" in message, "and how to fix it"


def test_it_is_refused_in_development_too_not_just_production():
    """Gating a cross-tenant hole on a deployment mode means the default
    configuration — the one every developer runs — is the unsafe one."""
    settings = _settings(
        f"{_entry('acme', ACME_KEY, 'chat+rag')},{_entry('globex', ACME_KEY, 'chat')}"
    )
    assert settings.env == "test"
    with pytest.raises(AmbiguousTenantKey):
        Authenticator(settings)


def test_the_order_does_not_decide_who_wins():
    """Whichever tenant happened to be configured last used to get access.
    Reversing the order must not turn a refusal into a pass."""
    entries = [_entry("acme", ACME_KEY, "chat+rag"), _entry("globex", ACME_KEY, "chat")]
    for order in (entries, list(reversed(entries))):
        with pytest.raises(AmbiguousTenantKey):
            Authenticator(_settings(",".join(order)))


def test_three_tenants_sharing_one_key_is_still_refused():
    entries = ",".join(
        _entry(tid, ACME_KEY, "chat") for tid in ("acme", "globex", "initech")
    )
    with pytest.raises(AmbiguousTenantKey):
        Authenticator(_settings(entries))


def test_a_collision_is_reported_even_when_it_is_not_the_production_check_that_found_it():
    """Authenticator catches it regardless of env, so the hole is closed even if
    the production boot check is bypassed."""
    settings = _settings(
        f"{_entry('acme', ACME_KEY, 'chat')},{_entry('globex', ACME_KEY, 'admin')}"
    )
    with pytest.raises(AmbiguousTenantKey):
        Authenticator(settings)


# ----------------------------------------------------- the production path --

def test_the_boot_check_names_the_two_tenants():
    settings = _settings(
        f"{_entry('acme', ACME_KEY, 'chat')},{_entry('globex', ACME_KEY, 'chat')}"
    )
    problems = settings._tenant_problems(settings.tenant_map())
    collisions = [p for p in problems if "share one API key hash" in p]
    assert len(collisions) == 1, problems
    assert "acme" in collisions[0] and "globex" in collisions[0]


def test_the_boot_check_does_not_complain_about_distinct_keys():
    settings = _settings(
        f"{_entry('acme', ACME_KEY, 'chat')},{_entry('globex', GLOBEX_KEY, 'chat')}"
    )
    problems = settings._tenant_problems(settings.tenant_map())
    assert not [p for p in problems if "share one API key hash" in p], problems


def test_a_collision_case_differs_only_by_hash_so_the_check_is_not_about_scopes():
    """Same key, wildly different scopes — the dangerous case, since the
    shadowed tenant's admin scopes would be unreachable and its data reachable."""
    settings = _settings(
        f"{_entry('acme', ACME_KEY, 'chat')},{_entry('globex', ACME_KEY, 'chat+rag+admin')}"
    )
    assert [p for p in settings._tenant_problems(settings.tenant_map())
            if "share one API key hash" in p]
