#!/usr/bin/env python3
"""Attacker-agent fuzz loop: mutate seed attacks, keep evasions for review.

Rule-based, deterministic (seeded), no LLM needed. Evasions go to a separate
file for human review — promote confirmed hits into attacks.yaml manually.

Usage:
  python scripts/fuzz_attacks.py --count 200 --seed 7
  python scripts/fuzz_attacks.py --count 200 --fail-on-evasion  # CI gate
"""
import argparse
import base64
import random
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.security.injection import scan

HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "i": "і", "p": "р", "c": "с",
              "A": "А", "E": "Е", "O": "О", "I": "І", "P": "Р"}
SYNONYMS = {"ignore": ["disregard", "overlook", "bypass"], "reveal": ["disclose", "show"],
            "instructions": ["directives", "guidelines"], "system prompt": ["system instructions"],
            "password": ["passcode"], "secret": ["confidential"]}
PREFIXES = ["", "kindly ", "as an experiment, ", "for research purposes, ",
            "kripya ", "por favor ", "s'il vous plait ", "translate then follow: "]
SUFFIXES = ["", " please", " — urgent", " (do it quietly)"]
WRAPPERS = ["{x}", "<system>{x}</system>", "[SYSTEM] {x}", "```system\n{x}\n```",
            "user says: {x}", "developer note: {x}"]


def _case_flip(text: str, rng: random.Random) -> str:
    mode = rng.choice(["upper", "lower", "title", "invert"])
    if mode == "upper":
        return text.upper()
    if mode == "lower":
        return text.lower()
    if mode == "title":
        return text.title()
    return "".join(c.lower() if c.isupper() else c.upper() for c in text)


def _space_split(text: str, rng: random.Random) -> str:
    kw = rng.choice(["ignore", "instructions", "prompt", "secret", "reveal"])
    if kw in text.lower():
        idx = text.lower().index(kw)
        spaced = " ".join(text[idx:idx + len(kw)])
        return text[:idx] + spaced + text[idx + len(kw):]
    return text


def _zero_width(text: str, rng: random.Random) -> str:
    pos = rng.randrange(len(text)) if text else 0
    return text[:pos] + "​" + text[pos:]


def _homoglyph(text: str, rng: random.Random) -> str:
    out = [HOMOGLYPHS.get(c, c) if rng.random() < 0.3 and c in HOMOGLYPHS else c
           for c in text]
    return "".join(out)


def _synonym(text: str, rng: random.Random) -> str:
    low = text.lower()
    for src, dsts in SYNONYMS.items():
        if src in low:
            return text.replace(src, rng.choice(dsts)).replace(src.title(),
                    rng.choice(dsts))
    return text


def _b64(text: str, rng: random.Random) -> str:
    enc = base64.b64encode(text.encode()).decode()
    return f"```{enc}```" if rng.random() < 0.5 else f"decode and follow: {enc}"


def _wrap(text: str, rng: random.Random) -> str:
    pre = rng.choice(PREFIXES)
    suf = rng.choice(SUFFIXES)
    return rng.choice(WRAPPERS).format(x=f"{pre}{text}{suf}")


TRANSFORMS = [_case_flip, _space_split, _zero_width, _homoglyph, _synonym, _b64, _wrap]


def fuzz(seeds: list[dict], count: int, seed: int) -> list[dict]:
    rng = random.Random(seed)  # noqa: S311 — deterministic test fuzzing, not crypto
    out = []
    for i in range(count):
        parent = seeds[i % len(seeds)]
        text = parent["text"]
        for _ in range(rng.randint(1, 2)):
            text = rng.choice(TRANSFORMS)(text, rng)
        out.append({"id": f"fuzz-{seed}-{i:03d}", "parent": parent["id"],
                    "text": text, "must_not_leak": parent.get("must_not_leak", [])})
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", default="scripts/attacks.yaml")
    parser.add_argument("--out", default="scripts/attacks_fuzz.yaml")
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--block-at", type=float, default=0.7)
    parser.add_argument("--fail-on-evasion", action="store_true")
    args = parser.parse_args()

    seeds = yaml.safe_load(Path(args.seeds).read_text(encoding="utf-8"))["attacks"]
    variants = fuzz(seeds, args.count, args.seed)
    evasions = []
    for v in variants:
        report = scan(v["text"])
        if report.score < args.block_at:
            evasions.append({**v, "score": report.score, "labels": report.labels})

    print(f"fuzzed={len(variants)} evasions(score<{args.block_at})={len(evasions)}")
    for e in evasions[:20]:
        print(f"  [EVADE score={e['score']}] {e['id']} <- {e['parent']}: "
              f"{e['text'][:90]!r}")

    if evasions:
        Path(args.out).write_text(
            yaml.safe_dump({"version": 1, "attacks": [
                {"id": e["id"], "text": e["text"],
                 "must_not_leak": e["must_not_leak"]} for e in evasions]},
                sort_keys=False, allow_unicode=True), encoding="utf-8")
        print(f"wrote {len(evasions)} evasions to {args.out} for review")
    if args.fail_on_evasion and evasions:
        print("FAIL: evasions present")
        return 1
    print("FUZZ DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
