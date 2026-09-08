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
SAVE_SQL = """INSERT INTO rag_chunks (tenant, source, seq, chunk_id, text)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (tenant, chunk_id) DO UPDATE SET
  source = EXCLUDED.source, seq = EXCLUDED.seq,
  text = EXCLUDED.text, updated_at = now()"""
LOAD_SQL = "SELECT tenant, source, seq, chunk_id, text FROM rag_chunks"


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

    def save(self, tenant: str, chunks: list[Chunk], conn=None) -> int:  # type: ignore[no-untyped-def]
        own = conn is None
        if own:
            conn = self._connect()
        try:
            with conn.cursor() as cur:
                for c in chunks:
                    cur.execute(SAVE_SQL, (tenant, c.source, c.seq, c.id, c.text))
            return len(chunks)
        finally:
            if own:
                conn.close()

    def load(self, conn=None) -> list[tuple[str, Chunk]]:  # type: ignore[no-untyped-def]
        """Returns (tenant, chunk) pairs so callers keep isolation on rebuild."""
        own = conn is None
        if own:
            conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(LOAD_SQL)
                rows = cur.fetchall()
        finally:
            if own:
                conn.close()
        out = []
        for tenant, source, seq, chunk_id, text in rows:
            doc_id = hashlib.sha256(source.encode()).hexdigest()[:12]
            out.append((tenant, Chunk(id=chunk_id, doc_id=doc_id, source=source, text=text,
                                      seq=seq, token_estimate=max(1, len(text) // 4))))
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
            for tenant, chunk in self.load(conn):
                grouped.setdefault(tenant, []).append(chunk)
            added = 0
            for tenant, chunks in grouped.items():
                store = stores.get(tenant)
                if store is None:
                    store = HybridRetriever()
                    stores[tenant] = store
                added += store.index(chunks)
            return added
        finally:
            if own:
                conn.close()
