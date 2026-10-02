"""The admin portal's three auth weaknesses, closed and pinned.

Each of these was a real finding, not a hypothetical:

  - `POST /admin/login` had no rate limit at all. The portal password is the
    one credential in this system that is a single shared secret, with no scope
    and no lockout, sitting in front of the controls that can pause every
    tenant. An unthrottled form there is a guessing oracle.
  - Changing the password left every issued session valid until it expired,
    because a cookie carried no link back to the credential that minted it.
  - Reading the audit trail was itself unaudited, which is a strange gap in a
    product whose pitch is provable evidence.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient  # noqa: F401  (fixtures import it)

from aegis.security import admin_session
from tests.test_admin_portal import app  # the application under test

ADMIN_ID = "operator"
ADMIN_PASSWORD = "correct-horse-battery-staple"  # noqa: S105 — test fixture
ADMIN_KEY = "sk-admin-key-xyz789"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A client for an admin-scoped deployment, mirroring test_admin_portal."""
    import asyncio
    import hashlib

    monkeypatch.chdir(tmp_path)
    from aegis.api.routes import STATE
    from aegis.config import Settings
    from aegis.gateway import build_gateway
    from aegis.metrics import metrics
    from aegis.security.auth import Authenticator

    settings = Settings(
        env="test",
        tenants=(
            f"ops:{hashlib.sha256(ADMIN_KEY.encode()).hexdigest()}:chat+rag+admin,"
            f"acme:{hashlib.sha256(b'other').hexdigest()}:chat+rag"
        ),
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
    STATE["settings"] = settings
    STATE["gateway"] = asyncio.run(build_gateway(settings))
    STATE["authenticator"] = Authenticator(settings)
    metrics.clear()
    with TestClient(app) as c:
        yield c
    STATE["gateway"].ops.clear()
    metrics.clear()


@pytest.fixture()
def client_bearer(client):
    """Same client, but carrying the admin bearer header.

    The audit routes need admin scope. The session cookie works too, but these
    tests are about the audit events rather than about which credential was
    used, and the bearer path is the one a scripted auditor would take.
    """
    client.headers.update({"Authorization": f"Bearer {ADMIN_KEY}"})
    return client


def _fresh_windows(*ids):
    from aegis.api import routes

    for i in ids:
        routes._LOGIN_LIMITER.reset(f"admin-login:{i}")


# ----------------------------------------------------------- rate limiting --


def test_repeated_wrong_passwords_are_throttled(client):
    _fresh_windows("testclient", f"testclient:{ADMIN_ID}")
    """A guessing run has to run out of budget, not just get slower."""
    from aegis.api import routes

    routes._LOGIN_LIMITER.reset("admin-login:testclient")
    routes._LOGIN_LIMITER.reset("admin-login:testclient:ops")

    codes = []
    for _ in range(25):
        r = client.post("/admin/login", json={"username": ADMIN_ID, "password": "wrong"})
        codes.append(r.status_code)
        if r.status_code == 429:
            break

    assert 429 in codes, f"25 wrong passwords never throttled: {codes}"
    assert codes.index(429) < 25, "throttle came too late to matter"


def test_a_throttled_login_says_when_to_retry(client):
    from aegis.api import routes

    for key in ("admin-login:testclient", "admin-login:testclient:ops"):
        routes._LOGIN_LIMITER.reset(key)
    for _ in range(25):
        if client.post("/admin/login", json={"username": ADMIN_ID, "password": "wrong"}).status_code == 429:
            break
    r = client.post("/admin/login", json={"username": ADMIN_ID, "password": "wrong"})
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_a_correct_login_after_typos_is_not_locked_out(client):
    _fresh_windows("testclient", f"testclient:{ADMIN_ID}")
    """A fumbled password must not spend an operator's budget for them.

    Without the reset on success, three typos followed by the right password
    would leave a real operator throttled — the exact outcome that gets a lockout
    policy disabled.
    """
    from aegis.api import routes

    for key in ("admin-login:testclient", "admin-login:testclient:ops"):
        routes._LOGIN_LIMITER.reset(key)
    for _ in range(3):
        client.post("/admin/login", json={"username": ADMIN_ID, "password": "nope"})

    ok = client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    assert ok.status_code == 200, ok.text
    assert client.get("/admin/session").json()["authenticated"] is True


def test_a_wrong_password_is_never_audited_with_the_guessed_id(client_bearer):
    """The limiter is in place, but the original decision stands.

    A failed login is not evidence, and logging the attempted id would turn the
    chain into a way to discover valid operator accounts. Counting rows cannot
    test this — reading the trail is itself recorded now — so the assertion is
    about what is *in* the chain, not how much of it there is.
    """
    _fresh_windows("testclient", "testclient:scout")
    for _ in range(4):
        client_bearer.post("/admin/login", json={"username": "scout", "password": "guess"})

    rows = client_bearer.get("/admin/audit", params={"limit": 500}).json()["records"]
    blob = " ".join(f"{r.get('event')} {r.get('tenant')} {r.get('payload')}" for r in rows)
    assert "scout" not in blob, "the guessed id was written to the chain"
    for forbidden in ("login_failed", "admin_login_failed", "auth_failure"):
        assert forbidden not in blob, f"{forbidden} appeared in the chain"


# ------------------------------------------------- password-change logout --


def test_changing_the_password_ends_every_live_session():
    """Revocation without a session table.

    The cookie is bound to a fingerprint of the credential that minted it, so a
    password change invalidates everything on the next request. Before this, a
    lockout meant waiting out the 8h TTL and a stolen cookie stayed usable for
    the same window.
    """
    key = "k" * 32
    old = admin_session.credential_fingerprint("ops", "old-password", key)
    cookie = admin_session.sign("ops", key, fingerprint=old)
    new = admin_session.credential_fingerprint("ops", "new-password", key)

    assert admin_session.verify(cookie, key, fingerprint=old) == "ops"
    assert admin_session.verify(cookie, key, fingerprint=new) is None


def test_a_cookie_does_not_survive_a_password_change_end_to_end(client):
    _fresh_windows("testclient", f"testclient:{ADMIN_ID}")
    from aegis.api import routes

    for key in ("admin-login:testclient", "admin-login:testclient:ops"):
        routes._LOGIN_LIMITER.reset(key)
    login = client.post("/admin/login", json={"username": ADMIN_ID, "password": ADMIN_PASSWORD})
    assert login.status_code == 200
    assert client.get("/admin/session").json()["authenticated"] is True

    # Simulate the operator rotating the password, then re-verifying the same
    # cookie against the new credential the way the request guard does.
    settings = routes._settings()
    new_fingerprint = admin_session.credential_fingerprint(
        "ops", "a-rotated-password", routes._admin_session_key(settings)
    )
    cookie = client.cookies.get(admin_session.COOKIE)
    key, _ = routes.admin_session_credentials(settings)
    assert admin_session.verify(cookie, key, fingerprint=new_fingerprint) is None


def test_the_fingerprint_does_not_disclose_the_password():
    key = "k" * 32
    fp = admin_session.credential_fingerprint("ops", "correct horse", key)
    assert "correct" not in fp and "horse" not in fp
    # Stable for the same credential, different for a different one.
    assert fp == admin_session.credential_fingerprint("ops", "correct horse", key)
    assert fp != admin_session.credential_fingerprint("ops", "battery staple", key)
    # And bound to the key, so it is not portable between deployments.
    assert fp != admin_session.credential_fingerprint("ops", "correct horse", "j" * 32)


# ------------------------------------------------------- audited the read --


def test_reading_the_audit_trail_is_itself_recorded(client_bearer):
    before = client_bearer.get("/admin/audit", params={"limit": 500}).json()["count"]
    client_bearer.get("/admin/audit", params={"limit": 10})
    after = client_bearer.get("/admin/audit", params={"limit": 500}).json()["count"]
    assert after > before, "reading the log left no trace"

    rows = client_bearer.get("/admin/audit", params={"limit": 500, "event": "admin_audit_read"}).json()
    assert rows["count"] >= 1
    record = rows["records"][0]
    assert record["sig_ok"] is True
    assert record["tenant"] == "ops"
    payload = record.get("payload") or {}
    assert payload.get("cross_tenant") is False


def test_a_cross_tenant_read_is_recorded_as_such(client_bearer):
    client_bearer.get("/admin/audit", params={"tenant": "acme", "limit": 5})
    rows = client_bearer.get("/admin/audit", params={"limit": 500, "event": "admin_audit_read"}).json()
    reads = [r for r in rows["records"] if (r.get("payload") or {}).get("cross_tenant")]
    assert reads, "a cross-tenant read was not distinguishable in the log"
    assert reads[0]["payload"]["scope"] == "acme"


def test_the_export_is_recorded_too(client_bearer):
    before = client_bearer.get("/admin/audit", params={"limit": 500}).json()["count"]
    assert client_bearer.get("/admin/audit/export", params={"limit": 5}).status_code == 200
    after = client_bearer.get("/admin/audit", params={"limit": 500}).json()["count"]
    assert after > before, "an export left no trace"


def test_audit_response_reports_ledger_coverage(client_bearer):
    """An operator reading the trail must be able to see whether it is whole.

    The returned rows come from the live file alone, so without a ledger block
    there is no way to tell a complete trail from one that lost a segment to a
    bad prune or a lost volume -- the same class of silent gap the reconciler
    was written to close.
    """
    body = client_bearer.get("/admin/audit", params={"limit": 5}).json()
    ledger = body.get("ledger")
    assert ledger is not None, "audit response must carry ledger coverage"
    for field in ("segments", "chains", "records", "complete", "per_segment"):
        assert field in ledger, f"ledger is missing {field}"
    assert ledger["complete"] is True, "a freshly written ledger should be whole"
