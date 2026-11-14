#!/usr/bin/env python3
"""CI eval gate. Exit code 1 if golden score < threshold.

Usage:
  python scripts/eval_gate.py --dataset src/aegis/evals/golden.yaml --threshold 0.85

Wire into GitHub Actions after tests: a PR that degrades answer quality cannot merge."""

import argparse
import asyncio
import hashlib
import json
import math
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.config import get_settings
from aegis.evals.dataset import KNOWLEDGE_BASE, load_dataset_spec
from aegis.evals.judges import HeuristicJudge
from aegis.evals.reports import build_report, compare_reports, fingerprint, write_report
from aegis.evals.runner import EvalResponse, run_evals
from aegis.gateway import build_gateway
from aegis.rag.service import RagService


def check_delta(score: float, baseline: float, max_drop: float) -> str | None:
    """Return failure message when score regressed vs baseline beyond max_drop."""
    if score < baseline - max_drop:
        return f"DELTA FAILED: {score:.2%} < baseline {baseline:.2%} - {max_drop:.0%} drop budget"
    return None


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="src/aegis/evals/golden.yaml")
    parser.add_argument("--threshold", type=float, default=0.85)
    parser.add_argument("--baseline", default="", help="JSON file with {'score': float} to gate on delta, not absolute")
    parser.add_argument("--max-drop", type=float, default=0.02, help="max allowed score drop vs baseline")
    parser.add_argument("--write-baseline", default="", help="write {'score','passed','total'} JSON after run")
    parser.add_argument("--split", choices=["development", "holdout", "all"], default="development")
    parser.add_argument("--allow-holdout", action="store_true", help="explicitly consume public holdout candidates")
    parser.add_argument("--provider", choices=["echo", "gemini", "groq", "openai", "anthropic", "gmi"], default="echo")
    parser.add_argument("--report-dir", type=Path, help="new directory for report.json and standalone report.html")
    parser.add_argument("--compare", type=Path, help="prior report.json; requires identical dataset, split, and judge")
    args = parser.parse_args()

    if not all(math.isfinite(v) and 0 <= v <= 1 for v in (args.threshold, args.max_drop)):
        parser.error("threshold and max-drop must be finite numbers between 0 and 1")
    if args.split != "development" and not args.allow_holdout:
        parser.error("holdout evaluation requires --allow-holdout; it consumes the holdout")
    if args.report_dir and args.report_dir.exists():
        parser.error("report directory already exists; choose a new directory")
    if args.baseline and args.write_baseline:
        parser.error("read and write baselines in separate runs")

    spec = load_dataset_spec(args.dataset)
    cases = [case for case in spec.cases if args.split == "all" or case.split == args.split]
    if not cases:
        parser.error("selected split has no cases")
    documents = (
        [doc.model_dump() for doc in spec.documents]
        if spec.documents is not None
        else [{"source": source, "text": text} for source, text in KNOWLEDGE_BASE]
    )
    case_snapshot = [asdict(case) for case in cases]
    judge_hash = hashlib.sha256(
        Path(__file__).resolve().parents[1].joinpath("src/aegis/evals/judges.py").read_bytes()
    ).hexdigest()
    manifest = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "dataset_version": spec.version,
        "dataset_file_sha256": hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest(),
        "split": args.split,
        "holdout_consumed": args.split != "development",
        "judge": "HeuristicJudge",
        "judge_sha256": judge_hash,
        "evaluation_fingerprint": fingerprint(
            {"cases": case_snapshot, "documents": documents, "judge_sha256": judge_hash, "split": args.split}
        ),
        "requested_provider": args.provider,
        "python_version": platform.python_version(),
        "packages": {name: version(name) for name in ("aegis-gateway", "pydantic", "httpx", "pyyaml")},
    }
    root = Path(__file__).resolve().parents[1]
    git = shutil.which("git")
    for key, command in (("git_commit", ["rev-parse", "HEAD"]), ("git_status", ["status", "--porcelain"])):
        if git:
            # Fixed read-only git arguments; no shell or user-supplied command.
            proc = subprocess.run([git, *command], cwd=root, capture_output=True, text=True, check=False)  # noqa: S603
            manifest[key] = proc.stdout.strip() if proc.returncode == 0 else "unavailable"
        else:
            manifest[key] = "unavailable"
    # A dirty tree needs a content identity too; a commit hash alone cannot reproduce it.
    manifest["source_sha256"] = fingerprint(
        {
            str(path.relative_to(root)): path.read_text(encoding="utf-8")
            for path in [*sorted((root / "src").rglob("*.py")), Path(__file__).resolve()]
        }
    )
    baseline_report = json.loads(args.compare.read_text(encoding="utf-8")) if args.compare else None
    if baseline_report is not None:
        # Validate the prior report before an opt-in live run can spend quota.
        compare_reports(baseline_report, baseline_report)
        if baseline_report["manifest"]["evaluation_fingerprint"] != manifest["evaluation_fingerprint"]:
            parser.error("comparison requires identical cases, corpus, split, and judge")

    # Independent in-memory corpus and scratch audit: never clear the API singleton
    # or connect the evaluator to the application's Redis/Postgres/object storage.
    with TemporaryDirectory(prefix="aegis-eval-") as scratch:
        settings = get_settings().model_copy(
            update={
                "env": "test",
                "providers": args.provider,
                "audit_path": str(Path(scratch) / "audit.jsonl"),
                "redis_url": "",
                "database_url": "",
                "audit_s3_bucket": "",
                "rate_limit_per_min": 10000,
                "daily_token_budget": 10_000_000,
            }
        )
        manifest["configuration"] = {
            "max_tokens": 300,
            "cache": False,
            "top_k": 4,
            "injection_soft_threshold": settings.injection_soft_threshold,
            "injection_block_threshold": settings.injection_block_threshold,
            "models": {name: getattr(settings, name) for name in ("gemini_model", "groq_model", "gmi_model")},
        }
        gateway = await build_gateway(settings)
        try:
            if args.provider not in gateway.registry:
                parser.error(f"requested provider {args.provider} is unavailable; configure its credentials")
            rag = RagService()
            for document in documents:
                rag.ingest(document["text"], document["source"], tenant="eval-runner")

            async def ask(question: str):
                ctx = rag.prepare(question, tenant="eval-runner")
                result = await gateway.handle_chat(
                    tenant_id="eval-runner",
                    messages=[{"role": "system", "content": ctx.system_prompt}, {"role": "user", "content": question}],
                    max_tokens=300,
                    use_cache=False,
                )
                completion = result.get("completion") or {}
                return EvalResponse(
                    result["answer"],
                    result["blocked"],
                    ctx.citations,
                    {
                        "provider": completion.get("provider"),
                        "model": completion.get("model"),
                        "requested_provider": args.provider,
                        "input_tokens": completion.get("input_tokens"),
                        "output_tokens": completion.get("output_tokens"),
                        "token_counts_estimated": completion.get("provider") == "echo",
                        "cost_usd": None,
                        "cached": result.get("cached", False),
                        "retrieved_context": ctx.system_prompt,
                    },
                )

            card = await run_evals(cases, ask, HeuristicJudge())
        finally:
            await gateway.aclose()

    manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
    report = build_report(card, manifest, case_snapshot, documents)
    comparison = compare_reports(baseline_report, report) if baseline_report is not None else None
    if comparison is not None:
        report["comparison"] = comparison
        print(json.dumps(comparison, indent=2))
    if args.report_dir:
        write_report(args.report_dir, report)
        print(f"Reports: {args.report_dir / 'report.html'} and report.json")

    summary = card.summary()
    print("=" * 56)
    print(f"  AEGIS EVAL GATE   score={summary['score']:.2%}  ({summary['passed']}/{summary['total']} passed)")
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
    if comparison and comparison["regressions"]:
        print("\nGATE FAILED: paired case regressions (even if gains offset the aggregate score)")
        return 1
    if args.write_baseline:
        Path(args.write_baseline).write_text(
            json.dumps({"score": summary["score"], "passed": summary["passed"], "total": summary["total"]}),
            encoding="utf-8",
        )
        print(f"baseline written to {args.write_baseline}")
    if args.baseline:
        try:
            base = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            baseline_score = float(base["score"])
            if not math.isfinite(baseline_score) or not 0 <= baseline_score <= 1:
                raise ValueError("baseline score must be finite and between 0 and 1")
            msg = check_delta(summary["score"], baseline_score, args.max_drop)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"\nDELTA FAILED: cannot read baseline ({exc})")
            return 1
        if msg:
            print(f"\n{msg}")
            return 1
        print(f"delta ok vs baseline {float(base['score']):.2%}")
    print("\nGATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
