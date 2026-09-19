"""RAG service: ingest documents, retrieve with hybrid fusion, build grounded,
cited prompts. Context blocks are formatted as [source:id] lines so both the
model and the eval judge can verify groundedness."""

import logging
from dataclasses import dataclass
from typing import Any

from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever, Retrieved

log = logging.getLogger("aegis.rag")


class RagPersistError(RuntimeError):
    """The durable copy of a document could not be changed.

    Raised only for deletions, never for writes: a failed write leaves the
    in-memory index (which is what answers queries) correct, while a failed
    delete would leave the two disagreeing in the direction that resurrects
    deleted content on restart.
    """


@dataclass
class RagAnswerContext:
    question: str
    system_prompt: str
    citations: list[dict]


class RagService:
    """Tenant-isolated RAG: each tenant gets its own HybridRetriever.

    No cross-tenant leakage — tenant A docs never surface in tenant B queries.
    Backward-compat: default tenant="default" preserves old single-tenant tests.
    """

    def __init__(self, top_k: int = 4, embed_provider=None) -> None:  # type: ignore[no-untyped-def]
        self._stores: dict[str, HybridRetriever] = {}
        self.top_k = top_k
        self._pg: Any = None
        self._embed = embed_provider

    def configure(self, database_url: str = "") -> str:
        """Attach Postgres source-of-truth once; reload persisted chunks.

        Returns 'postgres' when the DB is reachable, else 'memory'.
        Safe to call repeatedly; only the first successful attach wins.
        """
        if not database_url or self._pg is not None:
            return "postgres" if self._pg is not None else "memory"
        try:
            from aegis.store.db import PgChunkStore

            pg = PgChunkStore(database_url)
            loaded = pg.bootstrap(self._stores)
            self._pg = pg
            log.info("rag backend=postgres chunks=%d", loaded)
            return "postgres"
        except Exception:  # noqa: BLE001 — DB optional, memory keeps serving
            log.warning("rag backend=memory (postgres unreachable)")
            return "memory"

    def configure_embeddings(self, name: str = "", model: str = "") -> str:
        """Select embedding backend (legacy default). Returns active name."""
        from aegis.rag.embeddings import get_embed_provider

        self._embed = get_embed_provider(name, model)
        return getattr(self._embed, "name", "legacy")

    def _for(self, tenant: str) -> HybridRetriever:
        key = tenant or "default"
        if key not in self._stores:
            self._stores[key] = HybridRetriever(embed_provider=self._embed)
        return self._stores[key]

    @property
    def retriever(self) -> HybridRetriever:
        return self._for("default")

    @property
    def size(self) -> int:
        return sum(r.size for r in self._stores.values())

    def clear(self, tenant: str | None = None) -> None:
        if tenant is None:
            self._stores.clear()
        else:
            self._stores.pop(tenant, None)

    def ingest(self, text: str, source: str, tenant: str = "default") -> dict:
        store = self._for(tenant)
        chunks = chunk_document(text, source)
        # Replace semantics (M10): chunk IDs hash the body, so re-ingesting an
        # edited document mints new IDs and the previous generation would
        # linger — still retrievable, resurrectable on restart. Drop the old
        # generation first; the durable copy is pruned best-effort below.
        store.remove_source(source)
        added = store.index(chunks)
        embs = {c.id: store._embs[c.id] for c in chunks if c.id in store._embs}
        self._persist_best_effort(tenant, source, chunks, embs or None)
        return {
            "source": source,
            "chunks_created": len(chunks),
            "chunks_indexed": added,
            "index_size": store.size,
        }

    def _persist_best_effort(self, tenant: str, source: str, chunks: list,  # type: ignore[no-untyped-def]
                             embeddings: dict | None = None) -> bool:
        """Write-through to Postgres; False when absent/unreachable (memory kept)."""
        if self._pg is None:
            return False
        try:
            self._pg.save(tenant, chunks, embeddings=embeddings)
            self._pg.prune_source(tenant, source, {c.id for c in chunks})
            return True
        except Exception:  # noqa: BLE001 — persistence never blocks ingest
            log.warning("rag persist failed, memory index kept")
            return False

    def list_documents(self, tenant: str = "default") -> dict:
        """Inventory for the tenant's document manager."""
        store = self._for(tenant)
        docs = store.documents()
        return {
            "tenant": tenant,
            "backend": "postgres" if self._pg is not None else "memory",
            "documents": docs,
            "documents_total": len(docs),
            "chunks_total": store.size,
        }

    def delete_document(self, tenant: str, source: str) -> dict:
        """Remove a source from the durable store *and* the live index.

        Order matters. The durable delete runs first and is allowed to raise; if
        it fails the in-memory index is left untouched, so the gateway stays
        consistent and the caller gets an honest error instead of a success that
        the next restart would quietly undo. (The reverse order — memory first,
        DB best-effort — is the tempting one and it is wrong.)
        """
        store = self._for(tenant)
        persisted: int | None = None
        if self._pg is not None:
            try:
                persisted = self._pg.delete_source(tenant, source)
            except Exception as exc:  # noqa: BLE001 — translated to an honest 503
                raise RagPersistError(
                    f"could not remove '{source}' from durable storage; "
                    f"nothing was deleted ({type(exc).__name__})"
                ) from exc
        removed = store.remove_source(source)
        log.info("rag delete tenant=%s source=%s chunks=%d persisted=%s",
                 tenant, source, removed, persisted)
        return {
            "source": source,
            "chunks_removed": removed,
            "persisted_removed": persisted,
            "index_size": store.size,
        }

    def clear_tenant(self, tenant: str) -> dict:
        """Drop an entire tenant's index (memory + durable)."""
        store = self._for(tenant)
        persisted: int | None = None
        if self._pg is not None:
            for doc in store.documents():
                try:
                    persisted = (persisted or 0) + self._pg.delete_source(tenant, doc["source"])
                except Exception as exc:  # noqa: BLE001 — surfaced, not swallowed
                    raise RagPersistError(
                        f"could not clear durable storage ({type(exc).__name__})"
                    ) from exc
        count = store.size
        self._stores.pop(tenant, None)
        return {"tenant": tenant, "chunks_removed": count, "persisted_removed": persisted}

    def prepare(self, question: str, tenant: str = "default") -> RagAnswerContext:
        results: list[Retrieved] = self._for(tenant).retrieve(question, top_k=self.top_k)
        context_lines = [
            f"[{r.chunk.source}#chunk{r.chunk.seq}] {r.chunk.text}" for r in results
        ]
        system_prompt = (
            "You answer strictly from the provided context blocks. "
            "Cite sources as [source#chunkN]. If the context lacks the answer, say so.\n\n"
            + "\n".join(context_lines)
        ) if context_lines else (
            "No indexed context is available. Say that you don't have indexed information "
            "for this question."
        )
        citations = [
            {
                "source": r.chunk.source,
                "chunk": r.chunk.seq,
                "chunk_id": r.chunk.id,
                "score": r.score,
                "matched_by": r.matched_by,
            }
            for r in results
        ]
        return RagAnswerContext(
            question=question,
            system_prompt=f"tenant={tenant}; " + system_prompt,
            citations=citations,
        )


# module-level singleton used by the API layer
rag_service = RagService()
