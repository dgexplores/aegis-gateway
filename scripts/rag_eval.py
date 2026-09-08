#!/usr/bin/env python3
"""Retrieval eval: recall@k + MRR per strategy arm, with drift baseline.

Deterministic (no LLM calls): indexes the canonical eval knowledge base and
measures whether each grounded golden case retrieves its expected source doc.
The bm25/vector arms make it an A/B harness for the hybrid-fusion question;
--baseline turns it into a drift gate (any recall/MRR drop beyond tolerance
fails, so silent retrieval regressions can't merge).

Usage:
  python scripts/rag_eval.py [--top-k 4] [--min-recall 0.75]
      [--save-baseline scripts/rag_baseline.json]
      [--baseline scripts/rag_baseline.json --tolerance 0.0]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.evals.dataset import KNOWLEDGE_BASE, load_dataset  # noqa: E402
from aegis.rag.ingest import chunk_document  # noqa: E402
from aegis.rag.retriever import HybridRetriever  # noqa: E402

STRATEGIES = ("hybrid", "bm25", "vector")


def evaluate(top_k: int) -> dict:
    retriever = HybridRetriever()
    for source, text in KNOWLEDGE_BASE:
        retriever.index(chunk_document(text, source))
    cases = [c for c in load_dataset("src/aegis/evals/golden.yaml") if c.expect_source]

    per_strategy: dict[str, dict] = {}
    for strategy in STRATEGIES:
        recalls, rrs, misses = [], [], []
        for case in cases:
            hits = retriever.retrieve(case.question, top_k=top_k, strategy=strategy)
            rank = next((i for i, h in enumerate(hits, start=1)
                         if h.chunk.source == case.expect_source), None)
            if rank is None:
                recalls.append(0)
                rrs.append(0.0)
                misses.append(case.id)
            else:
                recalls.append(1)
                rrs.append(round(1 / rank, 4))
        per_strategy[strategy] = {
            "cases": len(cases),
            f"recall@{top_k}": round(sum(recalls) / len(recalls), 4) if recalls else 0.0,
            "mrr": round(sum(rrs) / len(rrs), 4) if rrs else 0.0,
            "misses": misses,
        }
    return per_strategy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--min-recall", type=float, default=0.75)
    parser.add_argument("--save-baseline", default="")
    parser.add_argument("--baseline", default="")
    parser.add_argument("--tolerance", type=float, default=0.0)
    args = parser.parse_args()

    report = evaluate(args.top_k)
    print(f"{'strategy':<8} {'recall@k':>8} {'mrr':>7}  misses")
    for strategy in STRATEGIES:
        row = report[strategy]
        print(f"{strategy:<8} {row[f'recall@{args.top_k}']:>8.2%} {row['mrr']:>7.3f}  "
              f"{','.join(row['misses']) or '-'}")

    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(report, indent=2) + "\n",
                                            encoding="utf-8")
        print(f"baseline saved to {args.save_baseline}")

    failed = False
    hybrid_recall = report["hybrid"][f"recall@{args.top_k}"]
    if hybrid_recall < args.min_recall:
        print(f"GATE FAILED: hybrid recall {hybrid_recall:.2%} < {args.min_recall:.0%}")
        failed = True

    if args.baseline:
        expected = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        for strategy in STRATEGIES:
            for metric in (f"recall@{args.top_k}", "mrr"):
                drop = expected[strategy][metric] - report[strategy][metric]
                if drop > args.tolerance:
                    print(f"DRIFT: {strategy} {metric} {expected[strategy][metric]} "
                          f"-> {report[strategy][metric]} (drop {drop:.4f})")
                    failed = True
        if not failed:
            print("no drift vs baseline")

    print("RAG EVAL PASSED" if not failed else "RAG EVAL FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
