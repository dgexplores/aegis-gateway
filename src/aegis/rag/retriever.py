"""Hybrid retriever: BM25 (lexical) + hashed n-gram vectors (semantic-ish),
fused with Reciprocal Rank Fusion (k=60).

Zero heavy dependencies: BM25 implemented directly; the embedding fallback is
a deterministic feature-hashing vectorizer — good enough to demonstrate hybrid
fusion and swap-ready for real embeddings (sentence-transformers / provider API)
via the same interface. Every result carries provenance for citation."""

import math
import re
from collections import Counter
from dataclasses import dataclass

from aegis.rag.ingest import Chunk

_RRF_K = 60
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "a", "an", "is", "are", "of", "to", "in", "and", "or",
    "for", "on", "with", "as", "by", "it", "this", "that", "be",
}


@dataclass
class Retrieved:
    chunk: Chunk
    score: float
    matched_by: str  # "bm25" | "vector" | "rrf"


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP and len(t) > 1]


def _hash_vec(tokens: list[str], dims: int = 512) -> Counter[int]:
    v: Counter[int] = Counter()
    for tok in tokens:
        v[hash(tok) % dims] += 1
    return v


def _cosine(a: Counter[int], b: Counter[int]) -> float:
    dot = sum(n * b.get(i, 0) for i, n in a.items())
    na = math.sqrt(sum(n * n for n in a.values()))
    nb = math.sqrt(sum(n * n for n in b.values()))
    return dot / (na * nb) if na and nb else 0.0


class HybridRetriever:
    def __init__(self) -> None:
        self._chunks: dict[str, Chunk] = {}
        self._doc_freq: Counter[str] = Counter()
        self._tf: dict[str, Counter[str]] = {}
        self._vecs: dict[str, Counter[int]] = {}
        self._total_docs = 0

    # -- indexing -----------------------------------------------------------

    def index(self, chunks: list[Chunk]) -> int:
        added = 0
        for ch in chunks:
            if ch.id in self._chunks:
                continue
            tokens = tokenize(ch.text)
            tf = Counter(tokens)
            self._chunks[ch.id] = ch
            self._tf[ch.id] = tf
            self._vecs[ch.id] = _hash_vec(tokens)
            for term in tf:
                self._doc_freq[term] += 1
            self._total_docs += 1
            added += 1
        return added

    @property
    def size(self) -> int:
        return len(self._chunks)

    # -- retrieval ------------------------------------------------------------

    def _bm25_scores(self, query_tokens: list[str]) -> dict[str, float]:
        if not self._total_docs:
            return {}
        k1, b = 1.5, 0.75
        avgdl = sum(sum(tf.values()) for tf in self._tf.values()) / max(self._total_docs, 1)
        scores: dict[str, float] = {}
        for cid, tf in self._tf.items():
            dl = sum(tf.values())
            s = 0.0
            for qt in query_tokens:
                f = tf.get(qt, 0)
                if not f:
                    continue
                n = self._doc_freq[qt]
                idf = math.log(1 + (self._total_docs - n + 0.5) / (n + 0.5))
                denom = f + k1 * (1 - b + b * dl / max(avgdl, 1))
                s += idf * (f * (k1 + 1)) / denom
            if s > 0:
                scores[cid] = s
        return scores

    def _vector_scores(self, query_tokens: list[str]) -> dict[str, float]:
        qv = _hash_vec(query_tokens)
        if not qv:
            return {}
        sims = ((cid, _cosine(qv, vec)) for cid, vec in self._vecs.items())
        return {cid: sim for cid, sim in sims if sim > 0.01}

    def retrieve(self, query: str, top_k: int = 5) -> list[Retrieved]:
        qtokens = tokenize(query)
        bm25 = self._bm25_scores(qtokens)
        vec = self._vector_scores(qtokens)

        bm25_rank = {cid: r for r, cid in enumerate(
            sorted(bm25, key=lambda c: bm25[c], reverse=True), start=1)}
        vec_rank = {cid: r for r, cid in enumerate(
            sorted(vec, key=lambda c: vec[c], reverse=True), start=1)}

        candidates = set(bm25_rank) | set(vec_rank)
        fused: dict[str, tuple[float, set[str]]] = {}
        for cid in candidates:
            score = 0.0
            sources: set[str] = set()
            if cid in bm25_rank:
                score += 1 / (_RRF_K + bm25_rank[cid])
                sources.add("bm25")
            if cid in vec_rank:
                score += 1 / (_RRF_K + vec_rank[cid])
                sources.add("vector")
            fused[cid] = (score, sources)

        ranked = sorted(fused.items(), key=lambda kv: kv[1][0], reverse=True)[:top_k]
        return [
            Retrieved(chunk=self._chunks[cid],
                      score=round(score, 6),
                      matched_by="+".join(sorted(sources)))
            for cid, (score, sources) in ranked
        ]
