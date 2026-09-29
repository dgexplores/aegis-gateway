"""The admin portal's own door.

Two things are being defended here, and they are not the same thing:

* the **portal login** must actually gate the portal — a wrong password, a
  forged cookie, a tampered cookie, an expired cookie and a missing cookie all
  have to be refused, and the cookie must not be readable from JavaScript;
* the **bearer token** must keep working on the same routes, because turning the
  portal login on cannot be allowed to break a monitoring script that was
  already scraping `/admin/overview`.

And the actions themselves: an operator can pause, kill, allow and override a
breaker over HTTP, each one audited, each one refusing to act on a tenant or
provider that does not exist.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from aegis.api.routes import STATE, app
from aegis.config import Settings
from aegis.gateway import build_gateway
from aegis.metrics import metrics
from aegis.security import admin_session

ADMIN_KEY = "sk-admin-key-xyz789"
TENANT_KEY = "sk-tenant-key-abc123"
ADMIN_ID = "operator"
ADMIN_PASSWORD = "correct-horse-battery-staple"  # noqa: S105 — a test fixture credential


def make_settings(tmp_path) -> Settings:
    return Settings(
        env="test",
        tenants=(
            # Comma separates tenants, '+' separates scopes within one.
            f"ops:{hashlib.sha256(ADMIN_KEY.encode()).hexdigest()}:chat+rag+admin,"
            f"acme:{hashlib.sha256(TENANT_KEY.encode()).hexdigest()}:chat+rag"
        ),
        providers="echo",
        rate_limit_per_min=1000,
        daily_token_budget=10_000_000,
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
        # Retain payload copies, or `tail_records` returns payload=None and the
        # actor assertion below would be checking nothing.
        audit_encrypt_key="test-encrypt-key-32-characters!!",
        admin_username=ADMIN_ID,
        admin_password=ADMIN_PASSWORD,
        admin_session_key="test-admin-session-key-32-chars-lol",
    )


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import asyncio

    settings = make_settings(tmp_path)
    STATE["settings"] = settings
    STATE["gateway"] = asyncio.run(build_gateway(settings))
    from aegis.security.auth import Authenticator

    STATE["authenticator"] = Authenticator(settings)
    metrics.clear()
    with TestClient(app) as c:
        yield c
    STATE["gateway"].ops.clear()
    metrics.clear()


def bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ------------------------------------------------------------- the login --

def test_session_reports_anonymous_before_login(client):
    body = client.get("/admin/session").json()
    assert body == {
        "authenticated": False, "user": None,
        "login_available": True, "demo_credentials": False,
    }


def test_the_right_id_and_password_gets_a_session(client):
    r = client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    assert r.status_code == 200 and r.json()["authenticated"] is True
    assert client.get("/admin/session").json()["user"] == ADMIN_ID


def test_a_wrong_password_is_refused(client):
    r = client.post("/admin/login", json={"username": ADMIN_ID, "password": "nope"})
    assert r.status_code == 401
    assert client.get("/admin/session").json()["authenticated"] is False


def test_a_wrong_id_is_refused(client):
    r = client.post("/admin/login", json={"username": "root", "password": ADMIN_PASSWORD})
    assert r.status_code == 401


def test_the_rejection_does_not_reveal_which_half_was_wrong(client):
    """Otherwise the form becomes a probe for valid ids."""
    bad_user = client.post("/admin/login", json={"username": "root", "password": "x"}).json()
    bad_pass = client.post("/admin/login", json={"username": ADMIN_ID, "password": "x"}).json()
    assert bad_user["detail"] == bad_pass["detail"]


def test_the_cookie_is_not_readable_from_javascript(client):
    """HttpOnly, or an XSS becomes an admin session."""
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    header = client.post(
        "/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD}
    ).headers.get("set-cookie", "")
    assert "httponly" in header.lower()
    assert "samesite=strict" in header.lower()


def test_a_forged_cookie_is_refused(client):
    client.cookies.set(admin_session.COOKIE, "made.up.value")
    assert client.get("/admin/controls").status_code == 401


def test_a_tampered_payload_is_refused_even_with_a_valid_shape(client):
    """Re-signing is the attacker's move; here they only get to edit the body."""
    key = make_settings(None).admin_session_key
    good = admin_session.sign(ADMIN_ID, key)
    body, _, sig = good.rpartition(".")
    forged_body = body[:-2] + ("aa" if not body.endswith("aa") else "bb")
    client.cookies.set(admin_session.COOKIE, f"{forged_body}.{sig}")
    assert client.get("/admin/controls").status_code == 401


def test_a_cookie_signed_with_another_key_is_refused(client):
    client.cookies.set(admin_session.COOKIE, admin_session.sign(ADMIN_ID, "some-other-key"))
    assert client.get("/admin/controls").status_code == 401


def test_an_expired_cookie_is_refused(client):
    key = make_settings(None).admin_session_key
    # Signed a year ago, so already outside any sane lifetime.
    client.cookies.set(admin_session.COOKIE, admin_session.sign(ADMIN_ID, key, -31_536_000))
    assert client.get("/admin/controls").status_code == 401


def test_logout_ends_the_session(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    assert client.get("/admin/controls").status_code == 200
    client.post("/admin/logout")
    assert client.get("/admin/controls").status_code == 401


def test_a_tenant_key_cannot_use_the_admin_portal(client):
    """`acme` has chat+rag and no admin scope, so the bearer fallback must not
    let it in either."""
    assert client.get("/admin/controls", headers=bearer(TENANT_KEY)).status_code == 403


def test_the_admin_bearer_token_still_works_alongside_the_login(client):
    """Turning the portal on must not break an existing scraper."""
    r = client.get("/admin/controls", headers=bearer(ADMIN_KEY))
    assert r.status_code == 200
    assert r.json()["actor"] == "bearer"


def test_no_credential_at_all_is_refused(client):
    assert client.get("/admin/controls").status_code == 401


# ------------------------------------------------------------ the actions --

def test_controls_lists_the_tenants_and_providers_an_operator_can_aim_at(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    body = client.get("/admin/controls").json()
    assert body["tenants"] == ["acme", "ops"]
    assert "echo" in body["providers"]
    assert body["killed"] is False


def test_pausing_a_tenant_over_http_actually_pauses_it(client):
    """Not just a 200: the next real request from that tenant must be refused."""
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    client.post("/admin/controls/tenant/acme/pause")

    out = client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]},
                      headers=bearer(TENANT_KEY))
    assert out.json()["blocked"] is True
    assert "paused" in out.json()["answer"].lower()


def test_resuming_over_http_puts_the_tenant_back(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    client.post("/admin/controls/tenant/acme/pause")
    client.post("/admin/controls/tenant/acme/resume")
    out = client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]},
                      headers=bearer(TENANT_KEY))
    assert out.json()["blocked"] is False


def test_an_allow_over_http_waives_the_soft_band(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    client.post("/admin/controls/tenant/acme/allow")
    assert "acme" in client.get("/admin/controls").json()["allowed_tenants"]


def test_revoking_an_allow_says_whether_one_was_in_force(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    client.post("/admin/controls/tenant/acme/allow")
    first = client.post("/admin/controls/tenant/acme/deny").json()
    second = client.post("/admin/controls/tenant/acme/deny").json()
    assert first["revoked"] is True
    assert second["revoked"] is False


def test_the_kill_switch_over_http_refuses_everyone(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    client.post("/admin/controls/kill", json={"on": True})
    out = client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]},
                      headers=bearer(TENANT_KEY))
    assert out.json()["operator"]["state"] == "killed"


def test_breaking_a_provider_over_http(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    body = client.post("/admin/controls/breaker/echo", json={"state": "open"}).json()
    assert body["breaker_overrides"] == {"echo": "open"}
    assert client.post("/admin/controls/breaker/echo",
                       json={"state": "auto"}).json()["breaker_overrides"] == {}


def test_pausing_a_tenant_that_does_not_exist_is_refused(client):
    """A typo must not look like a successful containment."""
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    r = client.post("/admin/controls/tenant/typo/pause")
    assert r.status_code == 404
    assert client.get("/admin/controls").json()["paused_tenants"] == []


def test_overriding_a_provider_that_does_not_exist_is_refused(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    assert client.post("/admin/controls/breaker/nope", json={"state": "open"}).status_code == 404


def test_a_breaker_state_it_cannot_honour_is_rejected_by_validation(client):
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    assert client.post("/admin/controls/breaker/echo", json={"state": "ajar"}).status_code == 422


def test_every_control_action_is_audited_with_who_did_it(client):
    """An operator's own decisions are evidence too."""
    client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    client.post("/admin/controls/tenant/acme/pause")
    client.post("/admin/controls/kill", json={"on": True})
    client.post("/admin/controls/breaker/echo", json={"state": "open"})

    events = [r["event"] for r in STATE["gateway"].audit.tail_records(limit=50)["records"]]
    assert {"control_tenant_paused", "control_kill_on", "control_breaker_override"} <= set(events)

    record = next(r for r in STATE["gateway"].audit.tail_records(limit=50)["records"]
                  if r["event"] == "control_tenant_paused")
    assert record["payload"]["actor"] == ADMIN_ID
    assert record["payload"]["tenant"] == "acme"


def test_a_failed_login_is_not_written_to_the_audit_chain(client):
    """A failed login is not evidence. Logging the guess would turn the chain
    into an oracle for hunting valid ids."""
    before = STATE["gateway"].audit.seq
    client.post("/admin/login", json={"username": "root", "password": "guess"})
    assert STATE["gateway"].audit.seq == before


def test_the_demo_credential_is_advertised_as_such(client, tmp_path, monkeypatch):
    """If an operator is on the published default, the portal says so rather
    than letting them believe it is a real secret."""
    monkeypatch.setitem(STATE["settings"].__dict__, "admin_password",
                        admin_session.DEMO_PASSWORD)
    monkeypatch.setitem(STATE["settings"].__dict__, "admin_username",
                        admin_session.DEMO_USERNAME)
    body = client.get("/admin/session").json()
    assert body["demo_credentials"] is True


# ------------------------------------------------- the module, on its own --

def test_verify_rejects_a_cookie_with_no_dot_in_it():
    assert admin_session.verify("nodothere", "k") is None


def test_verify_rejects_junk_in_the_signature_position():
    assert admin_session.verify("body.!!!not-base64!!!", "k") is None


def test_verify_rejects_a_well_signed_cookie_whose_body_is_not_an_object():
    import base64
    import json

    body = base64.urlsafe_b64encode(json.dumps(["not", "an", "object"]).encode()).decode().rstrip("=")
    import hashlib
    import hmac

    key = "k"
    sig = base64.urlsafe_b64encode(
        hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    assert admin_session.verify(f"{body}.{sig}", key) is None
