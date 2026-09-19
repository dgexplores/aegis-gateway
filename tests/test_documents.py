"""Document removal has to leave the index *correct*, not merely smaller.

Deleting chunks from a BM25 index is the easy half. The hard half is that the
statistics which rank everything else — `_doc_freq` and `_total_docs` — must
stop counting the deleted document. Get that wrong and a document you removed
keeps bending the ranking of every query that follows, silently.
"""

import pytest

from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever
from aegis.rag.service import RagPersistError, RagService


def index(retriever, text, source):
    return retriever.index(chunk_document(text, source))


def test_documents_groups_chunks_by_source():
    r = HybridRetriever()
    index(r, "Alpha policy covers leave. " * 40, "alpha.md")
    index(r, "Beta policy covers travel. " * 40, "beta.md")

    docs = r.documents()
    assert [d["source"] for d in docs] == ["alpha.md", "beta.md"]
    assert all(d["chunks"] >= 1 for d in docs)
    assert sum(d["chunks"] for d in docs) == r.size
    assert docs[0]["preview"]


def test_remove_source_drops_only_that_source():
    r = HybridRetriever()
    index(r, "Alpha policy covers leave entitlement.", "alpha.md")
    index(r, "Beta policy covers travel reimbursement.", "beta.md")
    size_before = r.size

    removed = r.remove_source("alpha.md")
    assert removed >= 1
    assert r.size == size_before - removed
    assert [d["source"] for d in r.documents()] == ["beta.md"]


def test_remove_missing_source_is_a_noop():
    r = HybridRetriever()
    index(r, "Only document.", "only.md")
    assert r.remove_source("nope.md") == 0
    assert r.size == 1


def test_bm25_statistics_stop_counting_deleted_documents():
    """The regression this guards: a deleted doc's terms staying in the corpus
    statistics and skewing every later ranking."""
    r = HybridRetriever()
    index(r, "The zebra migration schedule is published annually.", "zebra.md")
    index(r, "The travel policy covers economy fares.", "travel.md")
    index(r, "The leave policy covers annual entitlement.", "leave.md")

    assert r._doc_freq["zebra"] == 1
    assert r._total_docs == 3
    assert r.retrieve("zebra migration", top_k=3), "zebra should be findable first"

    r.remove_source("zebra.md")

    assert r._doc_freq["zebra"] == 0, "term must leave the corpus statistics"
    assert r._total_docs == 2, "document count must not still include the deleted doc"
    assert r.retrieve("zebra migration", top_k=3) == []
    # and the surviving documents are still rankable
    assert r.retrieve("leave policy entitlement", top_k=1)[0].chunk.source == "leave.md"


def test_removing_a_duplicate_of_a_shared_term_keeps_other_docs_rankable():
    r = HybridRetriever()
    index(r, "Annual leave entitlement is twenty days.", "a.md")
    index(r, "Annual leave entitlement is twenty five days.", "b.md")

    r.remove_source("a.md")
    hits = r.retrieve("annual leave entitlement", top_k=5)
    assert hits and all(h.chunk.source == "b.md" for h in hits)
    assert r._doc_freq["entitlement"] == 1


def test_reingesting_after_delete_works():
    r = HybridRetriever()
    index(r, "Warranty is thirty six months.", "w.md")
    r.remove_source("w.md")
    assert r.size == 0
    assert index(r, "Warranty is thirty six months.", "w.md") >= 1
    assert r.retrieve("warranty months", top_k=1)[0].chunk.source == "w.md"


def test_reingest_replaces_stale_chunks_m10():
    """M10: re-ingesting an edited doc must not leave the old text retrievable."""
    svc = RagService()
    svc.ingest("The cafeteria serves lunch from noon.", "cafe.md", tenant="acme")
    assert svc._for("acme").size >= 1
    svc.ingest("The cafeteria serves dinner from six in the evening.", "cafe.md", tenant="acme")
    hits = svc._for("acme").retrieve("cafeteria", top_k=10)
    assert hits, "re-ingested doc must stay retrievable"
    assert all("noon" not in h.chunk.text for h in hits), "old generation must be gone"
    assert any("dinner" in h.chunk.text for h in hits)


def test_reingest_prunes_durable_copy_m10():
    """M10: the Postgres copy is pruned to the new generation best-effort."""

    class _PruningPgStore:
        def __init__(self):
            self.rows: dict[str, str] = {}

        def save(self, tenant, chunks, embeddings=None):
            for c in chunks:
                self.rows[c.id] = c.text
            return len(chunks)

        def prune_source(self, tenant, source, keep_ids):
            doomed = [cid for cid, text in self.rows.items() if cid not in keep_ids]
            for cid in doomed:
                del self.rows[cid]
            return len(doomed)

    svc = RagService()
    svc._pg = _PruningPgStore()
    svc.ingest("The cafeteria serves lunch from noon.", "cafe.md", tenant="acme")
    assert len(svc._pg.rows) >= 1
    svc.ingest("Dinner from six.", "cafe.md", tenant="acme")
    assert all("noon" not in text for text in svc._pg.rows.values())


class _FailingPgStore:
    def delete_source(self, tenant, source):
        raise RuntimeError("database is down")


class _RecordingPgStore:
    def __init__(self):
        self.calls = []

    def delete_source(self, tenant, source):
        self.calls.append((tenant, source))
        return 3


def test_delete_document_is_memory_only_without_persistence():
    svc = RagService()
    svc.ingest("Refunds within thirty days of purchase.", "refunds.md", tenant="acme")
    result = svc.delete_document("acme", "refunds.md")
    assert result["chunks_removed"] >= 1
    assert result["persisted_removed"] is None
    assert result["index_size"] == 0


def test_failed_durable_delete_leaves_the_index_untouched():
    """Order matters: if the durable delete fails, nothing may be removed from
    memory. Reporting success would be undone by the next restart, which reloads
    the chunks from Postgres — a deletion that silently un-deletes itself."""
    svc = RagService()
    svc.ingest("Refunds within thirty days of purchase.", "refunds.md", tenant="acme")
    svc._pg = _FailingPgStore()

    with pytest.raises(RagPersistError):
        svc.delete_document("acme", "refunds.md")

    assert svc._for("acme").size > 0, "the document must still be there"
    assert [d["source"] for d in svc.list_documents("acme")["documents"]] == ["refunds.md"]


def test_successful_delete_clears_both_copies():
    svc = RagService()
    svc.ingest("Refunds within thirty days of purchase.", "refunds.md", tenant="acme")
    pg = _RecordingPgStore()
    svc._pg = pg

    result = svc.delete_document("acme", "refunds.md")
    assert pg.calls == [("acme", "refunds.md")]
    assert result["persisted_removed"] == 3
    assert result["index_size"] == 0


def test_list_documents_reports_the_backend():
    svc = RagService()
    svc.ingest("Travel is booked in the portal.", "travel.md", tenant="acme")
    assert svc.list_documents("acme")["backend"] == "memory"
    svc._pg = _RecordingPgStore()
    assert svc.list_documents("acme")["backend"] == "postgres"


def test_tenants_never_see_each_others_documents():
    svc = RagService()
    svc.ingest("Acme internal leave policy.", "acme-policy.md", tenant="acme")
    svc.ingest("Globex internal travel policy.", "globex-policy.md", tenant="globex")

    assert [d["source"] for d in svc.list_documents("acme")["documents"]] == ["acme-policy.md"]
    assert [d["source"] for d in svc.list_documents("globex")["documents"]] == ["globex-policy.md"]

    # deleting in one tenant cannot touch the other
    svc.delete_document("acme", "acme-policy.md")
    assert svc.list_documents("globex")["chunks_total"] > 0


def test_clear_tenant_removes_only_that_tenant():
    svc = RagService()
    svc.ingest("Acme internal leave policy.", "acme-policy.md", tenant="acme")
    svc.ingest("Globex internal travel policy.", "globex-policy.md", tenant="globex")

    result = svc.clear_tenant("acme")
    assert result["chunks_removed"] >= 1
    assert svc.list_documents("acme")["chunks_total"] == 0
    assert svc.list_documents("globex")["chunks_total"] > 0
