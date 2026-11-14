"""Eval runner: executes golden cases against an ask-function and produces a
scorecard. Used locally, in CI (via scripts/eval_gate.py), and as the regression
gate that blocks PRs which degrade answer quality."""

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from aegis.evals.dataset import GoldenCase
from aegis.evals.judges import HeuristicJudge, Judge, Verdict


@dataclass
class EvalResponse:
    answer: str
    blocked: bool
    citations: list[dict]
    metadata: dict = field(default_factory=dict)


AskFn = Callable[[str], Awaitable[tuple[str, bool, list[dict]] | EvalResponse]]


@dataclass
class CaseResult:
    verdict: Verdict
    latency_ms: float
    answer_preview: str
    question: str = ""
    category: str = "general"
    response: EvalResponse | None = None


@dataclass
class Scorecard:
    results: list[CaseResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.verdict.passed)

    @property
    def score(self) -> float:
        return round(self.passed / self.total, 4) if self.total else 0.0

    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.verdict.passed]

    def summary(self) -> dict:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.total - self.passed,
            "score": self.score,
            "p95_latency_ms": self.p95_latency(),
        }

    def p95_latency(self) -> float:
        if not self.results:
            return 0.0
        latencies = sorted(r.latency_ms for r in self.results)
        idx = max(0, round(0.95 * (len(latencies) - 1)))
        return round(latencies[idx], 1)


async def run_evals(cases: list[GoldenCase], ask: AskFn, judge: Judge | None = None) -> Scorecard:
    judge = judge or HeuristicJudge()
    card = Scorecard()
    for case in cases:
        start = time.perf_counter()
        try:
            response = await ask(case.question)
            if not isinstance(response, EvalResponse):
                response = EvalResponse(*response)
        except Exception as exc:  # transport failure counts as failure, never crash the run
            card.results.append(
                CaseResult(
                    verdict=Verdict(case.id, False, {"request_completed": False}, f"ask error: {type(exc).__name__}"),
                    latency_ms=(time.perf_counter() - start) * 1000,
                    answer_preview="<error>",
                    question=case.question,
                    category=case.category,
                )
            )
            continue
        latency = (time.perf_counter() - start) * 1000
        verdict = judge.evaluate(case, response.answer, response.blocked, response.citations)
        requested = response.metadata.get("requested_provider")
        if requested and not response.blocked:
            used_requested = response.metadata.get("provider") == requested
            verdict.checks["requested_provider_used"] = used_requested
            if not used_requested:
                verdict.passed = False
                verdict.reason = "requested provider unavailable; fallback is not model-quality evidence"
        card.results.append(CaseResult(verdict, latency, response.answer[:120], case.question, case.category, response))
    return card
