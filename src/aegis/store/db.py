"""Postgres source-of-truth for RAG chunks (Phase 2 persistence).

Design: Postgres holds canonical chunks per tenant; the in-memory
HybridRetriever stays the query engine (hashed vectors, no ML deps).
On boot `bootstrap()` reloads every tenant's index, so restarts and
redeploys keep answering from docs. Writes are write-through and
best-effort: a DB failure never fails the request path.

Connections use autocommit so the optional `vector` extension install
can't poison the schema transaction on servers without pgvector.
The table is forward-compatible with a future embedding column
(Phase 3); schema setup is idempotent, no migration tool needed
until schema v2 (then alembic).
"""

import hashlib
import logging

from aegis.rag.ingest import Chunk
from aegis.rag.retriever import HybridRetriever

log = logging.getLogger("aegis.store")

CREATE_EXTENSION = "CREATE EXTENSION IF NOT EXISTS vector"
CREATE_TABLE = """CREATE TABLE IF NOT EXISTS rag_chunks (
  tenant TEXT NOT NULL,
  source TEXT NOT NULL,
  seq INTEGER NOT NULL,
  chunk_id TEXT NOT NULL,
  text TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (tenant, chunk_id))"""
CREATE_INDEX = "CREATE INDEX IF NOT EXISTS idx_rag_chunks_tenant ON rag_chunks (tenant)"
ADD_EMB_COL = "ALTER TABLE rag_chunks ADD COLUMN IF NOT EXISTS embedding TEXT"
SAVE_SQL = """INSERT INTO rag_chunks (tenant, source, seq, chunk_id, text)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (tenant, chunk_id) DO UPDATE SET
  source = EXCLUDED.source, seq = EXCLUDED.seq,
  text = EXCLUDED.text, updated_at = now()"""
SAVE_EMB_SQL = """INSERT INTO rag_chunks (tenant, source, seq, chunk_id, text, embedding)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant, chunk_id) DO UPDATE SET
  source = EXCLUDED.source, seq = EXCLUDED.seq,
  text = EXCLUDED.text, embedding = EXCLUDED.embedding, updated_at = now()"""
LOAD_SQL = "SELECT tenant, source, seq, chunk_id, text FROM rag_chunks"
LOAD_EMB_SQL = "SELECT tenant, source, seq, chunk_id, text, embedding FROM rag_chunks"
DELETE_SOURCE_SQL = "DELETE FROM rag_chunks WHERE tenant = %s AND source = %s"


class PgChunkStore:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def _connect(self):
        import psycopg  # type: ignore[import-not-found]

        return psycopg.connect(self.dsn, autocommit=True, connect_timeout=5)

    def ensure_schema(self, conn) -> None:  # type: ignore[no-untyped-def]
        with conn.cursor() as cur:
            try:
                cur.execute(CREATE_EXTENSION)
            except Exception:  # noqa: BLE001 — servers without pgvector still work lexically
                log.warning("pgvector extension unavailable, lexical-only schema")
            cur.execute(CREATE_TABLE)
            cur.execute(CREATE_INDEX)
            try:
                cur.execute(ADD_EMB_COL)
            except Exception:  # noqa: BLE001 — old servers stay lexical-only
                log.warning("embedding column unavailable, lexical-only schema")

    def save(self, tenant: str, chunks: list[Chunk], conn=None,  # type: ignore[no-untyped-def]
             embeddings: dict[str, list[float]] | None = None):
        own = conn is None
        if own:
            conn = self._connect()
        try:
            import json as _json

            with conn.cursor() as cur:
                for c in chunks:
                    emb = (embeddings or {}).get(c.id)
                    if emb is None:
                        cur.execute(SAVE_SQL, (tenant, c.source, c.seq, c.id, c.text))
                    else:
                        try:
                            cur.execute(SAVE_EMB_SQL, (tenant, c.source, c.seq, c.id,
                                                       c.text, _json.dumps(emb)))
                        except Exception:  # noqa: BLE001 — old schema without column
                            cur.execute(SAVE_SQL, (tenant, c.source, c.seq, c.id, c.text))
            return len(chunks)
        finally:
            if own:
                conn.close()

    def delete_source(self, tenant: str, source: str, conn=None) -> int:  # type: ignore[no-untyped-def]
        """Durably remove a source's chunks. Returns rows deleted.

        Unlike `save`, this one *raises* on failure. A best-effort delete would
        let the gateway report "document removed" while the row survives — and
        `bootstrap()` would reload it on the next restart, silently resurrecting
        content someone believed they had deleted.
        """
        own = conn is None
        if own:
            conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(DELETE_SOURCE_SQL, (tenant, source))
                return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        finally:
            if own:
                conn.close()

    def load(self, conn=None) -> list:  # type: ignore[no-untyped-def]
        """Returns (tenant, chunk, embedding|None) triples; 2-tuple rows for legacy callers."""
        own = conn is None
        if own:
            conn = self._connect()
        try:
            import json as _json

            with conn.cursor() as cur:
                try:
                    cur.execute(LOAD_EMB_SQL)
                    rows = cur.fetchall()
                    has_emb = True
                except Exception:  # noqa: BLE001 — schema without embedding column
                    cur.execute(LOAD_SQL)
                    rows = cur.fetchall()
                    has_emb = False
        finally:
            if own:
                conn.close()
        out = []
        for row in rows:
            if has_emb and len(row) == 6:
                tenant, source, seq, chunk_id, text, emb_json = row
                emb = _json.loads(emb_json) if emb_json else None
            else:
                tenant, source, seq, chunk_id, text = row[:5]
                emb = None
            doc_id = hashlib.sha256(source.encode()).hexdigest()[:12]
            out.append((tenant, Chunk(id=chunk_id, doc_id=doc_id, source=source, text=text,
                                      seq=seq, token_estimate=max(1, len(text) // 4)), emb))
        return out

    def bootstrap(self, stores: dict[str, HybridRetriever], conn=None) -> int:  # type: ignore[no-untyped-def]
        """Ensure schema, load every chunk into per-tenant retrievers.

        Returns chunks newly indexed (deduped by deterministic ids).
        Raises on connection failure — caller (RagService.configure) falls
        back to memory mode.
        """
        own = conn is None
        if own:
            conn = self._connect()
        try:
            self.ensure_schema(conn)
            grouped: dict[str, list[Chunk]] = {}
            embs: dict[str, list[float]] = {}
            for item in self.load(conn):
                # load() yields (tenant, chunk, emb); tolerate legacy (tenant, chunk)
                tenant, chunk = item[0], item[1]
                emb = item[2] if len(item) > 2 else None
                grouped.setdefault(tenant, []).append(chunk)
                if emb:
                    embs[chunk.id] = emb
            added = 0
            for tenant, chunks in grouped.items():
                store = stores.get(tenant)
                if store is None:
                    store = HybridRetriever()
                    stores[tenant] = store
                added += store.index(chunks)
                for c in chunks:
                    if c.id in embs and c.id not in store._embs:
                        store._embs[c.id] = embs[c.id]
            return added
        finally:
            if own:
                conn.close()
