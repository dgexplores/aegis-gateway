from aegis.rag.embeddings import HashEmbedProvider, cosine, get_embed_provider, l2norm
from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever


def test_hash_embed_deterministic_and_normalized():
    p = HashEmbedProvider(dims=32)
    a = p.embed(["refund window thirty days"])[0]
    b = p.embed(["refund window thirty days"])[0]
    assert a == b
    assert abs(sum(x * x for x in a) - 1.0) < 1e-6


def test_cosine_self_one():
    p = HashEmbedProvider(dims=32)
    (v,) = p.embed(["hello world"])
    assert abs(cosine(v, v) - 1.0) < 1e-6
    assert l2norm([3.0, 4.0]) == [0.6, 0.8]


def test_legacy_default_unchanged():
    assert get_embed_provider("legacy") is None
    assert get_embed_provider("") is None
    r = HybridRetriever()
    assert r._embs == {}


def test_hash_provider_retrieval_grounded():
    r = HybridRetriever(embed_provider=HashEmbedProvider(dims=64))
    r.index(chunk_document("Refund window is 30 days with receipt. " * 3, "policy.md"))
    r.index(chunk_document("Completely unrelated zebra astronomy facts. " * 3, "other.md"))
    hits = r.retrieve("refund window?", top_k=2)
    assert hits and hits[0].chunk.source == "policy.md"


def test_embedding_failure_falls_back_lexical():
    class Boom:
        def embed(self, texts):
            raise RuntimeError("api down")

    r = HybridRetriever(embed_provider=Boom())
    r.index(chunk_document("Refund window is 30 days with receipt. " * 3, "policy.md"))
    hits = r.retrieve("refund window?", top_k=1)
    assert hits and "refund" in hits[0].chunk.text.lower()


def test_save_load_embedding_roundtrip():
    from aegis.store.db import PgChunkStore

    class FakeCursor:
        def __init__(self):
            self.saved = {}
            self.rows = []

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql, params=None):
            if sql.startswith("INSERT"):
                if len(params or []) == 6:
                    self.saved[params[3]] = params[5]
            if sql.startswith("SELECT") and "embedding" in sql:
                self.rows = [("acme", "p.md", 0, cid, "Refund window 30 days", js)
                             for cid, js in self.saved.items()]
            return self

        def fetchall(self):
            return self.rows

    class FakeConn:
        def __init__(self, cur):
            self.cur = cur

        def cursor(self):
            return self.cur

        def close(self):
            pass

    cur = FakeCursor()
    store = PgChunkStore("postgresql://x")
    chunks = chunk_document("Refund window is 30 days with receipt. " * 3, "p.md")
    embs = {c.id: [0.1, 0.2, 0.3] for c in chunks}
    store.save("acme", chunks, conn=FakeConn(cur), embeddings=embs)
    loaded = store.load(conn=FakeConn(cur))
    assert loaded and loaded[0][2] == [0.1, 0.2, 0.3]
