import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from eval_gate import check_delta
from grow_golden import grow, slug, validate_miss


def write_golden(path: Path, questions: list[str]) -> None:
    path.write_text(yaml.safe_dump({
        "version": 1,
        "cases": [{"id": f"c{i}", "question": q} for i, q in enumerate(questions)],
    }), encoding="utf-8")


def test_slug_stable_and_unique():
    assert slug("How many vacation days?") == slug("How many vacation days?")
    assert slug("How many vacation days?") != slug("How many sick days?")


def test_validate_miss_ok_and_bad():
    assert validate_miss({"question": "hi", "must_contain": ["x"]})["question"] == "hi"
    assert validate_miss({"question": ""}) is None
    assert validate_miss({"question": "hi", "must_contain": "x"}) is None
    assert validate_miss({"question": "hi", "requires_citation": "yes"}) is None


def test_grow_dedups_and_limits(tmp_path):
    g = tmp_path / "golden.yaml"
    write_golden(g, ["How many vacation days?"])
    misses = [
        {"question": "How many vacation days?"},  # dup question
        {"question": "What is the refund window?", "must_contain": ["30"],
         "expect_source": "policy.md", "requires_citation": True},
        {"question": ""},  # invalid
        {"question": "How do I reset my password?", "must_contain": ["portal"]},
    ]
    doc, added, skipped = grow(g, misses, limit=1)
    assert len(added) == 1 and skipped >= 1
    assert added[0]["question"] == "What is the refund window?"
    # not written until caller writes — file unchanged
    assert len(yaml.safe_load(g.read_text()).get("cases", [])) == 1


def test_grow_end_to_end_write(tmp_path):
    g = tmp_path / "golden.yaml"
    write_golden(g, ["q0"])
    misses = [{"question": f"prod question {i}?", "must_contain": ["x"]} for i in range(5)]
    doc, added, skipped = grow(g, misses, limit=3)
    g.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert len(yaml.safe_load(g.read_text())["cases"]) == 4


def test_check_delta():
    assert check_delta(0.9, 0.9, 0.02) is None
    assert check_delta(0.89, 0.9, 0.02) is None
    assert check_delta(0.87, 0.9, 0.02) is not None


def test_baseline_roundtrip(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"score": 1.0, "passed": 12, "total": 12}))
    assert check_delta(1.0, json.loads(base.read_text())["score"], 0.02) is None
