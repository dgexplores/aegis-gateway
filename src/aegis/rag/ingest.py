"""Document ingestion: cleaning + chunking with overlap.

Chunk sizes follow common practice (~200-500 tokens, 15% overlap) so retrieval
quality matches what production RAG teams ship. Deterministic IDs enable
idempotent re-ingestion."""

import hashlib
import re
from dataclasses import dataclass

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")
_WHITESPACE = re.compile(r"\s+")

TARGET_TOKENS = 220
OVERLAP_RATIO = 0.15


@dataclass(frozen=True)
class Chunk:
    id: str
    doc_id: str
    source: str
    text: str
    seq: int
    token_estimate: int


def _token_estimate(text: str) -> int:
    return max(1, len(text) // 4)


def clean(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()


def chunk_document(text: str, source: str) -> list[Chunk]:
    """Sentence-aware sliding-window chunking."""
    cleaned = clean(text)
    if not cleaned:
        return []
    doc_id = hashlib.sha256(source.encode()).hexdigest()[:12]

    sentences = _SENT_SPLIT.split(cleaned)
    # merge tiny sentences into workable units
    units: list[str] = []
    buf = ""
    for s in sentences:
        if _token_estimate(buf) < 40:
            buf = f"{buf} {s}".strip()
        else:
            units.append(buf)
            buf = s
    if buf:
        units.append(buf)

    chunks: list[Chunk] = []
    window: list[str] = []
    window_tokens = 0
    overlap_target = int(TARGET_TOKENS * OVERLAP_RATIO)

    def flush() -> None:
        nonlocal window, window_tokens
        if not window:
            return
        body = " ".join(window)
        cid_src = f"{doc_id}:{len(chunks)}:{body[:64]}"
        chunks.append(
            Chunk(
                id=hashlib.sha256(cid_src.encode()).hexdigest()[:16],
                doc_id=doc_id,
                source=source,
                text=body,
                seq=len(chunks),
                token_estimate=_token_estimate(body),
            )
        )
        # keep tail for overlap
        tail: list[str] = []
        tail_tokens = 0
        for u in reversed(window):
            t = _token_estimate(u)
            if tail_tokens + t > overlap_target:
                break
            tail.insert(0, u)
            tail_tokens += t
        window, window_tokens = tail, tail_tokens

    for unit in units:
        ut = _token_estimate(unit)
        if window_tokens + ut > TARGET_TOKENS and window:
            flush()
        window.append(unit)
        window_tokens += ut
    flush()
    return chunks
