"""RAG service: ingest documents, retrieve with hybrid fusion, build grounded,
cited prompts. Context blocks are formatted as [source:id] lines so both the
model and the eval judge can verify groundedness."""

from dataclasses import dataclass

from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever, Retrieved


@dataclass
class RagAnswerContext:
    question: str
    system_prompt: str
    citations: list[dict]


class RagService:
    def __init__(self, top_k: int = 4) -> None:
        self.retriever = HybridRetriever()
        self.top_k = top_k

    def ingest(self, text: str, source: str) -> dict:
        chunks = chunk_document(text, source)
        added = self.retriever.index(chunks)
        return {
            "source": source,
            "chunks_created": len(chunks),
            "chunks_indexed": added,
            "index_size": self.retriever.size,
        }

    def prepare(self, question: str, tenant: str) -> RagAnswerContext:
        results: list[Retrieved] = self.retriever.retrieve(question, top_k=self.top_k)
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
