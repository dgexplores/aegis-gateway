import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from aegis.evals.dataset import GoldenCase, load_dataset_spec
from aegis.evals.judges import HeuristicJudge
from aegis.evals.reports import build_report, compare_reports, write_report
from aegis.evals.runner import EvalResponse, run_evals


def test_negative_controls_cannot_earn_a_passing_grade():
    judge = HeuristicJudge()
    case = GoldenCase("qa", "How much leave?", must_contain=["23"], requires_citation=True, expect_source="leave.md")
    citations = [{"source": "leave.md", "chunk": 0}]
    assert judge.evaluate(case, "23 days [leave.md#chunk0]", False, citations).passed
    for answer, blocked, sources in (
        ("23 days", False, citations),  # retrieval is not an answer citation
        ("23 days [invented.md#chunk0]", False, citations),
        ("23 days [leave.md#chunk0] [invented.md#chunk1]", False, citations),
        ("23 days [leave.md#chunk0]", True, citations),  # false refusal
        ("23 days [leave.md#chunk0]", False, []),
        ("30 days [leave.md#chunk0]", False, citations),
    ):
        assert not judge.evaluate(case, answer, blocked, sources).passed


@pytest.mark.parametrize(
    "cases",
    [
        [{"id": "empty", "question": "No rules?"}],
        [{"id": "bad", "question": "q", "must_contain": [""]}],
        [{"id": "bad", "question": "q", "requires_citation": "false"}],
        [{"id": "bad", "question": "q", "must_contain": ["x"], "split": "train"}],
        [{"id": "bad", "question": "q", "expect_source": "missing.md"}],
        [
            {"id": "a", "question": "Same?", "must_contain": ["x"]},
            {"id": "b", "question": " same? ", "must_contain": ["x"], "split": "holdout"},
        ],
        [
            {"id": "a", "question": "q1", "must_contain": ["x"]},
            {"id": "a", "question": "q2", "must_contain": ["x"]},
        ],
    ],
)
def test_invalid_datasets_fail_before_running(tmp_path, cases):
    dataset = tmp_path / "invalid.json"
    dataset.write_text(json.dumps({"version": 1, "cases": cases}))
    with pytest.raises(ValueError):
        load_dataset_spec(dataset)


def test_shipped_datasets_validate_and_holdout_is_separate():
    root = Path(__file__).resolve().parents[1] / "src/aegis/evals"
    assert len(load_dataset_spec(root / "golden.yaml").cases) >= 60
    cases = load_dataset_spec(root / "experiments.yaml").cases
    assert sum(case.split == "development" for case in cases) == 14
    assert sum(case.split == "holdout" for case in cases) == 4


async def test_runner_records_fallback_and_transport_errors_without_leaking_secrets(tmp_path):
    cases = [GoldenCase(str(i), str(i), must_contain=["correct"]) for i in range(3)]

    async def ask(question):
        if question == "1":
            return EvalResponse("correct", False, [], {"requested_provider": "gemini", "provider": "echo"})
        if question == "2":
            raise RuntimeError("private credential must not appear in report")
        return "correct", False, []  # legacy callers still work

    card = await run_evals(cases, ask)
    assert card.passed == 1
    assert card.results[1].response.metadata["provider"] == "echo"
    assert card.results[2].verdict.checks == {"request_completed": False}
    report = build_report(card, {"judge_sha256": "fixture", "split": "development"}, [asdict(c) for c in cases], [])
    report["results"][0]["response"]["answer"] = "<script>alert('unsafe')</script>"
    write_report(tmp_path / "run", report)
    raw = (tmp_path / "run/report.json").read_text()
    html = (tmp_path / "run/report.html").read_text()
    assert "private credential" not in raw
    assert "<script>" not in html and "&lt;script&gt;" in html
    with pytest.raises(FileExistsError):
        write_report(tmp_path / "run", report)


async def test_paired_comparison_exposes_regressions_hidden_by_aggregate_gain():
    cases = [GoldenCase(str(i), str(i), must_contain=["correct"]) for i in range(2)]

    async def ask(question):
        return ("correct" if question == "0" else "wrong"), False, []

    card = await run_evals(cases, ask)
    baseline = build_report(card, {"judge_sha256": "fixture", "split": "development"}, [asdict(c) for c in cases], [])
    candidate = copy.deepcopy(baseline)
    candidate["results"][0]["verdict"]["passed"] = False
    candidate["results"][1]["verdict"]["passed"] = True
    comparison = compare_reports(baseline, candidate)
    assert comparison["score_delta"] == 0
    assert comparison["regressions"] == ["0"] and comparison["improvements"] == ["1"]
    candidate["results"].pop()
    with pytest.raises(ValueError, match="one result"):
        compare_reports(baseline, candidate)
    candidate = copy.deepcopy(baseline)
    candidate["manifest"]["evaluation_fingerprint"] = "different-corpus"
    with pytest.raises(ValueError, match="fingerprint"):
        compare_reports(baseline, candidate)
    candidate = copy.deepcopy(baseline)
    candidate["dataset"]["cases"][0]["question"] = "different question, stale fingerprint"
    with pytest.raises(ValueError, match="fingerprint"):
        compare_reports(baseline, candidate)
