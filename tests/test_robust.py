"""Robustness: readiness probe + audit rotation (Phase 1 guarantees)."""

import asyncio

from fastapi.testclient import TestClient

from aegis.api.routes import STATE, app
from aegis.config import Settings
from aegis.gateway import build_gateway
from aegis.security.audit import AuditChain

API_KEY = "sk-robust-key-1"


def _settings(tmp_path, **kw):
    import hashlib

    return Settings(
        env="test",
        tenants=f"acme:{hashlib.sha256(API_KEY.encode()).hexdigest()}:chat+rag",
        providers="echo",
        rate_limit_per_min=1000,
        daily_token_budget=10_000_000,
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
        audit_path=str(tmp_path / "audit.jsonl"),
        **kw,
    )


def test_readyz_ok_when_boot_chain_intact(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gw = asyncio.run(build_gateway(_settings(tmp_path)))
    STATE["gateway"] = gw
    from aegis.security.auth import Authenticator

    STATE["authenticator"] = Authenticator(_settings(tmp_path))
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200
        r = c.get("/readyz")
        assert r.status_code == 200
        assert r.json()["status"] == "ready"


def test_audit_rotation_keeps_verify_green(tmp_path):
    chain = AuditChain("test-audit-key-32-chars-minimum!!",
                       path=str(tmp_path / "audit.jsonl"), max_bytes=300)
    for i in range(20):
        chain.append("t", "ev", {"i": i})
    assert (tmp_path / "audit.jsonl.1").exists()
    ok, _ = chain.verify()
    assert ok is True


def test_probe_ok_on_long_chain_and_catches_tail_tamper(tmp_path):
    """M13: probe is O(1) and green on long chains; tampered tail -> not ready."""
    chain = AuditChain("test-audit-key-32-chars-minimum!!",
                       path=str(tmp_path / "audit.jsonl"))
    for i in range(200):
        chain.append("t", "ev", {"i": i})
    ok, msg = chain.probe()
    assert ok is True
    assert "length=200" in msg
    # tamper with the last line only
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    import json as _json

    rec = _json.loads(lines[-1])
    rec["event"] = "forged"
    lines[-1] = _json.dumps(rec)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    ok, msg = chain.probe()
    assert ok is False
    assert "seq=200" in msg
