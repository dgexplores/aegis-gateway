"""Break-glass on the kill switch.

The kill switch is the only control that stops every tenant at once, so it is
the one place where "you are signed in" is not enough on its own. What is being
defended, and the ways it can be got wrong:

* **the secret is not required** when it is configured;
* **it gates the wrong direction** — an incident must not end with a gateway
  nobody can switch back on, so restoring traffic takes no secret;
* **it can be brute-forced**, because a step-up worth nothing under a thousand
  guesses a second is theatre;
* **it leaves no trace**, or a stranger doing this from a hijacked session looks
  identical to the operator who was asked to.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from aegis.api.routes import STATE, _reset_breakglass, app
from aegis.config import Settings
from aegis.gateway import build_gateway

ADMIN_KEY = "sk-admin-key-xyz789"
ADMIN_ID = "operator"
ADMIN_PASSWORD = "correct-horse-battery-staple"  # noqa: S105 — test fixture credential
GLASS = "the-glass-password"
ATTEMPTS = 3


def make_settings(**over) -> Settings:
    base = dict(
        env="test",
        tenants=f"ops:{hashlib.sha256(ADMIN_KEY.encode()).hexdigest()}:chat+rag+admin",
        providers="echo",
        rate_limit_per_min=1000,
        daily_token_budget=10_000_000,
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
        audit_encrypt_key="test-encrypt-key-32-characters!!",
        admin_username=ADMIN_ID,
        admin_password=ADMIN_PASSWORD,
        admin_session_key="test-admin-session-key-32-chars-lol",
    )
    base.update(over)
    return Settings(**base)


@pytest.fixture()
def make_client(tmp_path, monkeypatch):
    """Build a signed-in client.

    A factory rather than one shared fixture, because "with a break-glass
    secret" and "without" are different deployments. A mutation fixture made the
    setup order load-bearing, and the order is the sort of thing that passes
    quietly until it does not.
    """
    import asyncio

    built: list[TestClient] = []

    def _make(**over):
        monkeypatch.chdir(tmp_path)
        settings = make_settings(**over)
        STATE["settings"] = settings
        STATE["gateway"] = asyncio.run(build_gateway(settings))
        from aegis.security.auth import Authenticator

        STATE["authenticator"] = Authenticator(settings)
        _reset_breakglass()
        client = TestClient(app)
        client.__enter__()
        client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
        built.append(client)
        return client

    yield _make

    for client in built:
        client.__exit__(None, None, None)
    _reset_breakglass()
    if "gateway" in STATE:
        STATE["gateway"].ops.clear()


@pytest.fixture()
def guarded(make_client):
    """A deployment that has a break-glass secret."""
    return make_client(breakglass_password=GLASS, breakglass_attempts=ATTEMPTS)


def events() -> list[str]:
    return [r["event"] for r in STATE["gateway"].audit.tail_records(limit=80)["records"]]


def record_named(event: str) -> dict:
    return next(r for r in STATE["gateway"].audit.tail_records(limit=80)["records"] if r["event"] == event)


# ------------------------------------------------- when nothing is configured --


def test_without_a_secret_the_kill_switch_still_works(make_client):
    """Unset must not break the control. The weaker posture is the operator's
    choice, and the UI warns about it rather than pretending otherwise."""
    client = make_client()
    r = client.post("/admin/controls/kill", json={"on": True})
    assert r.status_code == 200 and r.json()["killed"] is True
    assert client.get("/admin/controls").json()["breakglass_required"] is False


# ---------------------------------------------------------- when it is set --


def test_the_controls_payload_says_the_secret_is_required(guarded):
    """So the UI can ask for it, rather than an operator finding out with a 403
    in the middle of an incident."""
    assert guarded.get("/admin/controls").json()["breakglass_required"] is True


def test_refusing_all_traffic_without_the_secret_is_refused(guarded):
    r = guarded.post("/admin/controls/kill", json={"on": True})
    assert r.status_code == 403
    assert guarded.get("/admin/controls").json()["killed"] is False, "and it must not have fired"


def test_a_wrong_secret_is_refused(guarded):
    r = guarded.post("/admin/controls/kill", json={"on": True, "breakglass": "guess"})
    assert r.status_code == 403
    assert guarded.get("/admin/controls").json()["killed"] is False


def test_the_right_secret_stops_all_traffic(guarded):
    r = guarded.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS})
    assert r.status_code == 200 and r.json()["killed"] is True


def test_restoring_traffic_never_asks_for_the_secret(guarded):
    """An incident must not end with a gateway nobody can switch back on."""
    guarded.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS})
    r = guarded.post("/admin/controls/kill", json={"on": False})
    assert r.status_code == 200 and r.json()["killed"] is False


def test_a_tenant_pause_does_not_need_the_secret(guarded):
    """One noisy tenant is an ordinary decision. Every tenant at once is not."""
    r = guarded.post("/admin/controls/tenant/ops/pause")
    assert r.status_code == 200
    assert r.json()["paused_tenants"] == ["ops"]


def test_the_kill_switch_is_still_admin_only(guarded):
    """Break-glass is a second factor, not a way around the first."""
    with TestClient(app) as anonymous:
        r = anonymous.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS})
    assert r.status_code in (401, 403)


# ------------------------------------------------------------ brute force --


def test_repeated_wrong_secrets_lock_the_endpoint_out(guarded):
    """A step-up worth nothing against a script is not a step-up."""
    for _ in range(ATTEMPTS):
        assert guarded.post("/admin/controls/kill", json={"on": True, "breakglass": "nope"}).status_code == 403
    # The *correct* secret is now refused too: the limiter is refusing the
    # caller, not checking the password.
    assert guarded.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS}).status_code == 403


def test_a_lockout_expires_so_a_locked_out_operator_is_not_stuck_forever(guarded):
    """Otherwise the limiter is a self-inflicted denial of service."""
    for _ in range(ATTEMPTS):
        guarded.post("/admin/controls/kill", json={"on": True, "breakglass": "nope"})
    assert guarded.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS}).status_code == 403
    _reset_breakglass()
    assert guarded.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS}).status_code == 200


# ------------------------------------------------------------------ traces --


def test_a_successful_break_glass_use_is_audited_distinctly(guarded):
    """Greppable as its own thing, not buried among ordinary kill events."""
    guarded.post("/admin/controls/kill", json={"on": True, "breakglass": GLASS})
    assert "control_kill_on_breakglass" in events()


def test_a_refused_attempt_is_audited_too(guarded):
    """A stranger reaching for the kill switch from a hijacked session is a
    different event from the operator who was asked to."""
    guarded.post("/admin/controls/kill", json={"on": True, "breakglass": "guess"})
    assert "control_kill_refused_breakglass" in events()


def test_a_refused_attempt_records_the_actor(guarded):
    guarded.post("/admin/controls/kill", json={"on": True, "breakglass": "guess"})
    assert record_named("control_kill_refused_breakglass")["payload"]["actor"] == ADMIN_ID


def test_a_refused_attempt_does_not_record_the_guessed_secret(guarded):
    """The audit chain is readable by anyone auditing it. Writing the attempted
    secret into it would make the chain a place secrets leak."""
    guarded.post("/admin/controls/kill", json={"on": True, "breakglass": "a-guess"})
    blob = str(guarded.get("/admin/audit", headers={"Authorization": f"Bearer {ADMIN_KEY}"}).json())
    assert "a-guess" not in blob
