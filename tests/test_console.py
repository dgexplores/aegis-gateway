"""The console is part of the product, so it gets the same treatment as the API.

Two things are worth pinning. First, the console must be self-contained: a
gateway sold into regulated and air-gapped environments cannot depend on a CDN,
and a strict CSP is only possible if nothing inline is required. Second, the
console must actually call the endpoints that exist — a dashboard that silently
references a renamed route is a broken capability, not a cosmetic bug.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from aegis.api.middleware import SecurityHeadersMiddleware
from aegis.api.routes import STATE, app
from aegis.config import Settings
from aegis.gateway import build_gateway

API_KEY = "sk-console-test-key"
ROOT = None


def _root():
    from pathlib import Path

    return Path(__file__).resolve().parents[1] / "src" / "aegis"


def make_settings(tmp_path) -> Settings:
    return Settings(
        env="test",
        tenants=f"acme:{hashlib.sha256(API_KEY.encode()).hexdigest()}:chat+rag+admin",
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


def template() -> str:
    return (_root() / "templates" / "dashboard.html").read_text(encoding="utf-8")


def script() -> str:
    return (_root() / "static" / "dashboard.js").read_text(encoding="utf-8")


def stylesheet() -> str:
    return (_root() / "static" / "dashboard.css").read_text(encoding="utf-8")


# --- self-contained assets -----------------------------------------------------


def test_dashboard_and_assets_are_served(client):
    assert client.get("/dashboard").status_code == 200
    for path in ("/static/dashboard.css", "/static/dashboard.js"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} not served"


def test_dashboard_references_local_assets_only(client):
    html = template()
    assert "/static/dashboard.css" in html
    assert "/static/dashboard.js" in html
    for remote in ("cdn.tailwindcss.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
                   "fonts.gstatic.com", "unpkg.com"):
        assert remote not in html, f"the console must not depend on {remote}"
    # No attribute may fetch over the network. (The inline SVG favicon carries an
    # xmlns URI — that is a namespace identifier, not a request, so check the
    # attributes that actually cause fetches.)
    for attr in ('src="http', "src='http", 'href="http', "href='http", 'url(http'):
        assert attr not in html, f"remote fetch in the markup: {attr}"


def test_assets_are_clean_too():
    for name, text in (("dashboard.js", script()), ("dashboard.css", stylesheet())):
        for remote in ("cdn.", "googleapis", "jsdelivr", "unpkg", "@import url(http"):
            assert remote not in text, f"{name} must not reference {remote}"


def test_dashboard_has_no_inline_script_or_style_blocks():
    """Inline blocks would force 'unsafe-inline' back into the CSP."""
    html = template()
    assert 'style="' not in html, "inline style attributes would weaken the CSP"
    assert "<style" not in html
    # every <script> must be an external src reference
    assert html.count("<script") == html.count("<script src=")


def test_csp_forbids_inline_and_remote_code():
    csp = SecurityHeadersMiddleware.HEADERS["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert "http" not in csp, "no remote origin should be allowed"
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_static_responses_still_carry_security_headers(client):
    r = client.get("/static/dashboard.js")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


# --- the console must track the real API ---------------------------------------


def test_console_calls_endpoints_that_exist(client):
    """UI/API drift check: every path the console fetches must actually route."""
    js = script()
    paths = {
        "/v1/chat": "POST",
        "/v1/chat/stream": "POST",
        "/v1/rag/query": "POST",
        "/v1/rag/ingest": "POST",
        "/v1/rag/documents": "GET",
        "/v1/rag/delete": "POST",
        "/admin/audit": "GET",
        "/admin/audit/export": "GET",
        "/admin/status": "GET",
    }
    for path in paths:
        assert f"'{path}" in js or f"`{path}" in js or f"{path}?" in js, (
            f"the console never calls {path}"
        )

    # and the route table agrees
    declared = {r.path for r in app.routes if hasattr(r, "path")}
    for path in paths:
        assert path in declared, f"{path} is not routed by the app"


def test_console_has_no_browser_storage():
    for text in (template(), script()):
        assert "localStorage" not in text
        assert "sessionStorage" not in text
        assert "indexedDB" not in text


def test_console_surfaces_the_evidence_the_backend_provides():
    """Each of these is a capability the review flagged as invisible in the UI."""
    js = script()
    for token in ("outbound", "pii_masked", "audit_seq", "sig_ok", "link_ok",
                  "payload_ok", "request_id", "cached"):
        assert token in js, f"the console does not surface '{token}'"


def test_console_escapes_interpolated_values():
    """Anything the operator can influence must go through esc()."""
    js = script()
    assert "function esc(" in js or "const esc =" in js
    # no template literal may interpolate a raw dynamic value into innerHTML
    for raw in ("${d.source}", "${r.event}", "${row.tenant}"):
        idx = js.find(raw)
        assert idx == -1 or "esc(" in js[max(0, idx - 30):idx], (
            f"{raw} is interpolated without escaping"
        )
