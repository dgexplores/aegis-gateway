"""Cross-worker reads: two service instances sharing one Postgres must agree.

Each uvicorn worker keeps its own in-memory index, but Postgres is the
shared source of truth. Today a document ingested on worker A is invisible
on worker B until restart — ingest-vs-list split-brain across processes.
"""

from aegis.rag.service import RagService


class SharedFakePg:
    """In-memory stand-in for PgChunkStore: one object, many readers."""

    def __init__(self):
        self.rows: dict[tuple[str, str], tuple[str, int, str]] = {}
        # (tenant, chunk_id) -> (source, seq, text)

    def save(self, tenant, chunks, embeddings=None):
        for c in chunks:
            self.rows[(tenant, c.id)] = (c.source, c.seq, c.text)
        return len(chunks)

    def delete_source(self, tenant, source):
        doomed = [k for k, (s, _, _) in self.rows.items()
                  if k[0] == tenant and s == source]
        for k in doomed:
            del self.rows[k]
        return len(doomed)

    def prune_source(self, tenant, source, keep_ids):
        doomed = [k for k, (s, _, _) in self.rows.items()
                  if k[0] == tenant and s == source and k[1] not in keep_ids]
        for k in doomed:
            del self.rows[k]
        return len(doomed)

    def list_source_ids(self, tenant):
        grouped: dict[str, list[str]] = {}
        for (t, cid), (s, _, _) in self.rows.items():
            if t == tenant:
                grouped.setdefault(s, []).append(cid)
        return grouped

    def load_source(self, tenant, source):
        import hashlib

        from aegis.rag.ingest import Chunk

        out = []
        for (t, cid), (s, seq, text) in self.rows.items():
            if t == tenant and s == source:
                doc_id = hashlib.sha256(s.encode()).hexdigest()[:12]
                out.append((Chunk(id=cid, doc_id=doc_id, source=s, text=text,
                                  seq=seq, token_estimate=max(1, len(text) // 4)), None))
        return out


def _two_services_sharing_pg():
    pg = SharedFakePg()
    first, second = RagService(), RagService()
    first._pg = pg
    second._pg = pg
    return first, second


def test_ingest_on_one_instance_visible_to_another_sharing_postgres():
    """The split-brain: worker A ingests, worker B must answer from it."""
    first, second = _two_services_sharing_pg()
    first.ingest("The zebra migration schedule is published annually.", "zebra.md",
                 tenant="acme")

    ctx = second.prepare("zebra migration", tenant="acme")

    assert any(c["source"] == "zebra.md" for c in ctx.citations), \
        "sibling worker's document must be retrievable"


def test_delete_on_one_instance_hidden_from_another_sharing_postgres():
    """Deletes must propagate too, or B resurrects what A removed."""
    first, second = _two_services_sharing_pg()
    first.ingest("The zebra migration schedule is published annually.", "zebra.md",
                 tenant="acme")
    assert second.prepare("zebra migration", tenant="acme").citations
    first.delete_document("acme", "zebra.md")

    ctx = second.prepare("zebra migration", tenant="acme")

    assert all(c["source"] != "zebra.md" for c in ctx.citations), \
        "sibling worker must stop serving the deleted document"


def test_memory_mode_reads_stay_local_without_postgres():
    """No PG attached: today's behavior is unchanged, no sync attempted."""
    first, second = RagService(), RagService()
    first.ingest("The zebra migration schedule is published annually.", "zebra.md",
                 tenant="acme")

    ctx = second.prepare("zebra migration", tenant="acme")

    assert ctx.citations == []
