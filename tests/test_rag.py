from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever

SAMPLE = (
    "Employees receive twenty paid vacation days per calendar year. "
    "Vacation requests must be approved by your manager in the HR portal. "
) * 6 + (
    "The maximum expense reimbursement without prior approval is $75 per transaction. "
    "Receipts are required for anything above ten dollars. "
    "Finance reviews all claims monthly and audits random samples for compliance. "
) * 5


def test_chunking_creates_chunks_with_ids():
    chunks = chunk_document(SAMPLE, source="handbook.md")
    assert len(chunks) >= 2
    ids = {c.id for c in chunks}
    assert len(ids) == len(chunks)
    assert all(c.source == "handbook.md" for c in chunks)


def test_chunking_idempotent_same_source():
    c1 = chunk_document(SAMPLE, "handbook.md")
    c2 = chunk_document(SAMPLE, "handbook.md")
    assert [c.id for c in c1] == [c.id for c in c2]


def test_hybrid_retrieval_finds_right_chunk():
    chunks = chunk_document(SAMPLE, "handbook")
    r = HybridRetriever()
    r.index(chunks)
    hits = r.retrieve("how many paid vacation days do I get?", top_k=3)
    assert hits
    top_text = hits[0].chunk.text.lower()
    assert "vacation" in top_text
    # hybrid: at least one hit matched both lexical and vector signals
    assert any(h.matched_by == "bm25+vector" for h in hits)


def test_rrf_prefers_dual_matches():
    chunks = chunk_document(SAMPLE, "handbook")
    r = HybridRetriever()
    r.index(chunks)
    dual = [h for h in r.retrieve("expense reimbursement limit $75", top_k=5)
            if h.matched_by == "bm25+vector"]
    single = [h for h in r.retrieve("expense reimbursement limit $75", top_k=5)
              if "+" not in h.matched_by]
    if dual and single:
        assert max(h.score for h in dual) > max(h.score for h in single)
