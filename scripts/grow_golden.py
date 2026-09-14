#!/usr/bin/env python3
"""Grow the golden eval set from production misses (12 -> 100 roadmap).

Misses file: JSONL, one per line:
  {"question": "...", "must_contain": ["..."], "expect_source": "doc.md",
   "requires_citation": true}

Usage:
  python scripts/grow_golden.py --misses prod_misses.jsonl --limit 20
  python scripts/grow_golden.py --misses prod_misses.jsonl --dry-run
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(question: str) -> str:
    words = SLUG_RE.sub(" ", question.lower()).split()[:6]
    digest = hashlib.sha256(question.encode()).hexdigest()[:6]
    return f"prod-{'-'.join(words) or 'q'}-{digest}"


def normalize(question: str) -> str:
    return re.sub(r"\s+", " ", question.strip().lower())


def load_misses(path: Path) -> list[dict]:
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"skip line {i}: bad json ({exc})")
            continue
        out.append(obj)
    return out


def validate_miss(obj: dict) -> dict | None:
    q = obj.get("question", "")
    if not isinstance(q, str) or not (1 <= len(q) <= 8000):
        return None
    case: dict = {"id": obj.get("id") or slug(q), "question": q}
    for key in ("must_contain", "forbidden"):
        if key in obj and obj[key] is not None:
            vals = obj[key]
            if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals):
                return None
            case[key] = vals
    for key in ("requires_citation", "attack_like"):
        if key in obj and obj[key] is not None:
            if not isinstance(obj[key], bool):
                return None
            case[key] = obj[key]
    if obj.get("expect_source") is not None:
        if not isinstance(obj["expect_source"], str):
            return None
        case["expect_source"] = obj["expect_source"]
    return case


def grow(golden_path: Path, misses: list[dict], limit: int) -> tuple[dict, list[dict], int]:
    doc = yaml.safe_load(golden_path.read_text(encoding="utf-8"))
    cases = doc.get("cases", [])
    seen_ids = {c["id"] for c in cases}
    seen_q = {normalize(c["question"]) for c in cases}
    added = []
    skipped = 0
    for miss in misses:
        if len(added) >= limit:
            break
        case = validate_miss(miss)
        if case is None:
            skipped += 1
            continue
        if case["id"] in seen_ids or normalize(case["question"]) in seen_q:
            skipped += 1
            continue
        seen_ids.add(case["id"])
        seen_q.add(normalize(case["question"]))
        cases.append(case)
        added.append(case)
    doc["cases"] = cases
    return doc, added, skipped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--misses", required=True)
    parser.add_argument("--golden", default="src/aegis/evals/golden.yaml")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    misses_path = Path(args.misses)
    if not misses_path.exists():
        print(f"misses file not found: {misses_path}")
        return 1
    golden_path = Path(args.golden)
    misses = load_misses(misses_path)
    before = len(yaml.safe_load(golden_path.read_text(encoding="utf-8")).get("cases", []))
    doc, added, skipped = grow(golden_path, misses, args.limit)
    if args.dry_run:
        print(f"would add {len(added)} cases, skipped {skipped} (now {before})")
        for c in added:
            print(f"  + {c['id']}: {c['question'][:80]}")
        return 0
    golden_path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
                           encoding="utf-8")
    print(f"golden now {len(doc['cases'])} cases (+{len(added)}, skipped {skipped})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
