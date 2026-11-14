"""Inspectable local experiment records and paired regression comparisons."""

import hashlib
import json
from dataclasses import asdict
from html import escape
from pathlib import Path

from aegis.evals.runner import Scorecard


def fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def build_report(card: Scorecard, manifest: dict, cases: list[dict], documents: list[dict]) -> dict:
    manifest = dict(manifest)
    manifest["evaluation_fingerprint"] = fingerprint(
        {"cases": cases, "documents": documents, "judge_sha256": manifest["judge_sha256"], "split": manifest["split"]}
    )
    categories = sorted({result.category for result in card.results})
    return {
        "schema_version": 1,
        "manifest": manifest,
        "dataset": {"cases": cases, "documents": documents},
        "summary": card.summary(),
        "by_category": {
            category: Scorecard([r for r in card.results if r.category == category]).summary()
            for category in categories
        },
        "results": [asdict(result) for result in card.results],
        "limitations": [
            "Substring and citation checks do not establish factual correctness or general model quality.",
            "A valid citation marker establishes source identity, not support for every claim in the answer.",
            "Echo results exercise the pipeline; they do not measure a language model.",
            "Echo token counts are estimates. Cost is unmeasured and reported as null.",
            "Public holdout candidates are AI-assisted examples, not an independent secret benchmark.",
        ],
    }


def compare_reports(baseline: dict, candidate: dict) -> dict:
    for report in (baseline, candidate):
        if report.get("schema_version") != 1:
            raise ValueError("unsupported report schema")
        manifest = report["manifest"]
        snapshot = {**report["dataset"], "judge_sha256": manifest["judge_sha256"], "split": manifest["split"]}
        if fingerprint(snapshot) != manifest["evaluation_fingerprint"]:
            raise ValueError("report fingerprint does not match its dataset snapshot")
    if baseline["manifest"]["evaluation_fingerprint"] != candidate["manifest"]["evaluation_fingerprint"]:
        raise ValueError("comparison requires identical cases, corpus, split, and judge")

    def outcomes(report: dict) -> dict[str, bool]:
        results = report["results"]
        indexed = {result["verdict"]["case_id"]: result["verdict"]["passed"] for result in results}
        expected = {case["id"] for case in report["dataset"]["cases"]}
        if not indexed or len(indexed) != len(results) or set(indexed) != expected:
            raise ValueError("report must have exactly one result per selected case")
        if any(type(passed) is not bool for passed in indexed.values()):
            raise ValueError("verdict outcomes must be boolean")
        return indexed

    before, after = outcomes(baseline), outcomes(candidate)
    if before.keys() != after.keys():
        raise ValueError("comparison requires the same case ids")
    return {
        "paired_cases": len(before),
        "regressions": sorted(key for key in before if before[key] and not after[key]),
        "improvements": sorted(key for key in before if not before[key] and after[key]),
        "unchanged": sum(before[key] == after[key] for key in before),
        "score_delta": round((sum(after.values()) - sum(before.values())) / len(before), 4),
        "note": "Paired descriptive comparison; no statistical significance claim.",
    }


def write_report(directory: Path, report: dict) -> None:
    """Create a new report directory; never overwrite a previous experiment."""
    raw = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False)
    rows = []
    for result in report["results"]:
        verdict = result["verdict"]
        status = "PASS" if verdict["passed"] else "FAIL"
        rows.append(
            f"<tr><th scope='row'>{escape(verdict['case_id'])}</th><td>{status}</td>"
            f"<td>{escape(result['category'])}</td><td>{result['latency_ms']:.1f} ms</td>"
            f"<td><details><summary>{escape(verdict['reason'])}</summary>"
            f"<pre>{escape(json.dumps(result, indent=2, ensure_ascii=False))}</pre></details></td></tr>"
        )
    summary = report["summary"]
    html = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>AEGIS evaluation report</title>"
        "<style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:1100px}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.6rem;text-align:left}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer}"
        "@media(max-width:600px){body{margin:1rem auto}table{display:block;overflow-x:auto}}</style>"
        "<main><h1>AEGIS evaluation report</h1>"
        f"<p>{summary['passed']} / {summary['total']} passed ({summary['score']:.1%}). "
        f"p95 end-to-end latency: {summary['p95_latency_ms']} ms.</p>"
        "<p><a href='report.json'>Download the complete JSON record</a></p><ul>"
        + "".join(f"<li>{escape(item)}</li>" for item in report["limitations"])
        + "</ul><h2>Cases</h2><table><caption>Expand each verdict to inspect its evidence.</caption>"
        "<thead><tr><th scope='col'>Case</th><th scope='col'>Result</th><th scope='col'>Category</th>"
        "<th scope='col'>Latency</th><th scope='col'>Evidence</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table><h2>Run record</h2><details><summary>Configuration, dataset, and comparison</summary>"
        f"<pre>{escape(raw)}</pre></details></main></html>"
    )
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "report.json").write_text(raw + "\n", encoding="utf-8")
    (directory / "report.html").write_text(html, encoding="utf-8")
