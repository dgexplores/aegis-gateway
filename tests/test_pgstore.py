"""PgChunkStore with a fake connection: SQL shape + tenant isolation on rebuild."""

from aegis.rag.ingest import chunk_document
from aegis.rag.service import RagService
from aegis.store.db import PgChunkStore


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.executed: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        return self

    def fetchall(self):
        return self.rows


class FakeConn:
    def __init__(self, rows=None):
        self.cur = FakeCursor(rows)
        self.closed = False

    def cursor(self):
        return self.cur

    def close(self):
        self.closed = True


def test_ensure_schema_creates_table_and_index():
    conn = FakeConn()
    PgChunkStore("postgresql://x").ensure_schema(conn)
    stmts = [sql for sql, _ in conn.cur.executed]
    assert any("CREATE TABLE IF NOT EXISTS rag_chunks" in s for s in stmts)
    assert any("idx_rag_chunks_tenant" in s for s in stmts)


def test_save_carries_tenant_per_chunk():
    chunks = chunk_document("Refunds within 30 days with receipt. " * 4, "policy.md")
    conn = FakeConn()
    n = PgChunkStore("postgresql://x").save("acme", chunks, conn=conn)
    assert n == len(chunks) >= 1
    for sql, params in conn.cur.executed:
        assert "INSERT INTO rag_chunks" in sql
        assert params[0] == "acme"


def test_bootstrap_rebuilds_per_tenant_without_leak():
    rows = [
        ("acme", "policy.md", 0, "c1", "Refund window is 30 days with receipt."),
        ("acme", "policy.md", 1, "c2", "Unused vacation rolls over once."),
        ("other", "notes.md", 0, "c9", "Completely unrelated zebra facts."),
    ]
    store = PgChunkStore("postgresql://x")
    stores: dict = {}
    added = store.bootstrap(stores, conn=FakeConn(rows))
    assert added == 3
    assert set(stores) == {"acme", "other"}
    hits = stores["acme"].retrieve("refund window?", top_k=3)
    assert hits and "refund" in hits[0].chunk.text.lower()
    other_hits = stores["other"].retrieve("refund window?", top_k=3)
    assert all("refund" not in h.chunk.text.lower() for h in other_hits)


def test_bootstrap_idempotent_on_rebuild():
    rows = [("acme", "policy.md", 0, "c1", "Refunds within 30 days with receipt.")]
    store = PgChunkStore("postgresql://x")
    stores: dict = {}
    assert store.bootstrap(stores, conn=FakeConn(rows)) == 1
    assert store.bootstrap(stores, conn=FakeConn(rows)) == 0


def test_rag_configure_defaults_to_memory():
    assert RagService().configure("") == "memory"


def test_rag_write_through_failure_never_blocks_ingest():
    class BoomStore:
        def save(self, *args, **kwargs):
            raise RuntimeError("db down")

    svc = RagService()
    svc._pg = BoomStore()
    out = svc.ingest("Refunds within 30 days with receipt. " * 4, "t.md", tenant="acme")
    assert out["chunks_indexed"] >= 1
