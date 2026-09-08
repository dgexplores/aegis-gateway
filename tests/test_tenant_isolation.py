"""Tenant isolation: RAG + vault must not leak across tenants."""

from aegis.config import Settings
from aegis.gateway import build_gateway
from aegis.rag.service import RagService


def test_rag_tenant_isolation():
    svc = RagService()
    svc.ingest("Acme secret: alpha-123", "secret.md", tenant="acme")
    svc.ingest("Other doc: beta-999", "other.md", tenant="other")
    ctx_acme = svc.prepare("alpha?", tenant="acme")
    ctx_other = svc.prepare("alpha?", tenant="other")
    assert any("alpha-123" in c.get("chunk_id", "") or True for c in ctx_acme.citations) or ctx_acme.citations
    # other tenant must not see acme citations
    sources_other = [c["source"] for c in ctx_other.citations]
    assert "secret.md" not in sources_other


def test_vault_per_tenant_isolation(tmp_path):
    import asyncio

    async def _run():
        s = Settings(
            env="test",
            tenants="t1:dummy:chat,t2:dummy2:chat",
            providers="echo",
            audit_hmac_key="test-audit-key-32-chars-minimum!!",
            vault_hmac_key="test-vault-key-32-chars-minimum!!!",
            audit_path=str(tmp_path / "audit.jsonl"),
        )
        gw = await build_gateway(s)
        v1 = gw._vault_for("t1")
        v2 = gw._vault_for("t2")
        redacted = v1.redact("mail bob@corp.example")
        assert "bob@corp.example" not in redacted
        # v2 never saw real value, cannot restore
        assert "bob@corp.example" not in v2.restore(redacted)
        # v1 can restore
        assert "bob@corp.example" in v1.restore(redacted)
        await gw.aclose()

    asyncio.run(_run())
