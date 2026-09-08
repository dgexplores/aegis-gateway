#!/usr/bin/env python3
"""CI eval gate. Exit code 1 if golden score < threshold.

Usage:
  python scripts/eval_gate.py --dataset src/aegis/evals/golden.yaml --threshold 0.85

Wire into GitHub Actions after tests: a PR that degrades answer quality cannot merge."""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.config import get_settings
from aegis.evals.dataset import KNOWLEDGE_BASE, load_dataset
from aegis.evals.judges import HeuristicJudge
from aegis.evals.runner import run_evals
from aegis.gateway import build_gateway
from aegis.rag.service import rag_service


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="src/aegis/evals/golden.yaml")
    parser.add_argument("--threshold", type=float, default=0.85)
    args = parser.parse_args()

    settings = get_settings()
    gateway = await build_gateway(settings)
    try:
        rag_service.clear()
        for source, text in KNOWLEDGE_BASE:
            rag_service.ingest(text, source, tenant="eval-runner")

        cases = load_dataset(args.dataset)
        judge = HeuristicJudge()

        async def ask(question: str):
            ctx = rag_service.prepare(question, tenant="eval-runner")
            result = await gateway.handle_chat(
                tenant_id="eval-runner",
                messages=[
                    {"role": "system", "content": ctx.system_prompt},
                    {"role": "user", "content": question},
                ],
                max_tokens=300,
            )
            completion = result.get("completion") or {}
            return (
                result["answer"],
                result["injection"]["blocked"],
                result.get("citations") or ctx.citations,
                completion,
            )

        async def ask_adapter(question: str):
            answer, blocked, citations, _ = await ask(question)
            return answer, blocked, citations

        card = await run_evals(cases, ask_adapter, judge)
    finally:
        await gateway.aclose()

    summary = card.summary()
    print("=" * 56)
    print(f"  AEGIS EVAL GATE   score={summary['score']:.2%}  "
          f"({summary['passed']}/{summary['total']} passed)")
    print(f"  p95 latency: {summary['p95_latency_ms']} ms   threshold: {args.threshold:.0%}")
    print("=" * 56)
    for r in card.results:
        mark = "PASS" if r.verdict.passed else "FAIL"
        print(f"  [{mark}] {r.verdict.case_id:<28} {r.verdict.reason}")
        if not r.verdict.passed:
            print(f"         preview: {r.answer_preview!r}")

    if summary["score"] < args.threshold:
        print(f"\nGATE FAILED: {summary['score']:.2%} < {args.threshold:.0%}")
        return 1
    print("\nGATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
