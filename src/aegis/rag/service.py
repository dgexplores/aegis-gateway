"""RAG service: ingest documents, retrieve with hybrid fusion, build grounded,
cited prompts. Context blocks are formatted as [source:id] lines so both the
model and the eval judge can verify groundedness."""

import logging
from dataclasses import dataclass
from typing import Any

from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever, Retrieved

log = logging.getLogger("aegis.rag")


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

    def __init__(self, top_k: int = 4) -> None:
        self._stores: dict[str, HybridRetriever] = {}
        self.top_k = top_k
        self._pg: Any = None

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

    def _for(self, tenant: str) -> HybridRetriever:
        key = tenant or "default"
        if key not in self._stores:
            self._stores[key] = HybridRetriever()
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
        added = store.index(chunks)
        self._persist_best_effort(tenant, chunks)
        return {
            "source": source,
            "chunks_created": len(chunks),
            "chunks_indexed": added,
            "index_size": store.size,
        }

    def _persist_best_effort(self, tenant: str, chunks: list) -> bool:
        """Write-through to Postgres; False when absent/unreachable (memory kept)."""
        if self._pg is None:
            return False
        try:
            self._pg.save(tenant, chunks)
            return True
        except Exception:  # noqa: BLE001 — persistence never blocks ingest
            log.warning("rag persist failed, memory index kept")
            return False

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
