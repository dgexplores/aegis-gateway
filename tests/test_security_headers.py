"""Security regression tests: headers, error hygiene, no persisted secrets.

Encodes Standard §7 (headers), §6.1 (token storage), §13 (error shape) as
executable assertions so regressions fail in CI, not production.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from aegis.api.middleware import SecurityHeadersMiddleware
from aegis.api.routes import STATE, app
from aegis.config import Settings
from aegis.gateway import build_gateway

API_KEY = "sk-sec-test-key"


def make_settings(tmp_path) -> Settings:
    return Settings(
        env="test",
        tenants=f"sec:{hashlib.sha256(API_KEY.encode()).hexdigest()}:chat+rag",
        providers="echo",
        rate_limit_per_min=1000,
        daily_token_budget=10_000_000,
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
        audit_path=str(tmp_path / "audit.jsonl"),
    )


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import asyncio

    STATE["gateway"] = asyncio.run(build_gateway(make_settings(tmp_path)))
    from aegis.security.auth import Authenticator

    STATE["authenticator"] = Authenticator(make_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_security_headers_on_all_responses(client):
    for path in ("/healthz", "/metrics", "/dashboard"):
        r = client.get(path)
        assert r.status_code == 200
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert "max-age=31536000" in r.headers["Strict-Transport-Security"]


def test_error_responses_carry_headers_and_no_stack(client):
    r = client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 401
    assert "Traceback" not in r.text and "traceback" not in r.text
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    body = r.json()
    assert set(body) == {"detail"}


def test_dashboard_never_persists_keys(client):
    html = client.get("/dashboard").text
    assert "localStorage" not in html
    assert "sessionStorage" not in html


def test_middleware_declares_expected_header_set():
    assert set(SecurityHeadersMiddleware.HEADERS) == {
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
    }
