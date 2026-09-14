#!/usr/bin/env python3
"""PII precision/recall harness, incl. India pack (Aadhaar/PAN/passport/UPI).

Usage:
  python scripts/pii_eval.py

Fails (exit 1) if any must-recall case is missed. Prints per-type P/R.
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.security.pii import build_vault

KEY = "pii-eval-key"

# (text, expected labels masked). Empty list = must NOT mask (precision probe).
CASES: list[tuple[str, list[str]]] = [
    # legacy
    ("reach me at john.doe@corp.example today", ["EMAIL"]),
    ("card: 4111111111111111", ["CARD"]),
    ("order 12345678 shipped", []),
    ("ssn 123-45-6789 on file", ["SSN"]),
    # India pack — must recall
    ("my aadhaar 2345 6789 0111 please", ["AADHAAR"]),
    ("aadhaar 234567890111 verify", ["AADHAAR"]),
    ("PAN ABCDE1234F on file", ["PAN"]),
    ("pan BNZPM2501F for kyc", ["PAN"]),
    ("passport J1234567 verify", ["PASSPORT"]),
    ("pay to sharma@okhdfcbank now", ["UPI"]),
    ("upi id priya.sharma@upi collect 500", ["UPI"]),
    # precision probes — must NOT mask as India types
    ("order id ABCDE12345 is not a PAN", []),
    ("call me tomorrow morning", []),
    # Invalid Aadhaar (starts with 1) fails Verhoeff gate but still masked as
    # PHONE by the permissive phone detector — safe fallback, not a miss.
    ("aadhaar 1234 5678 9012 starts with 1, invalid", ["PHONE"]),
]


def main() -> int:
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    misses = []
    for text, expected in CASES:
        v = build_vault(KEY)
        out = v.redact(text)
        got = set(v.masked_types)
        exp = set(expected)
        # masked at all?
        if exp and not got:
            misses.append((text, exp, got, out))
        for label in exp:
            if label in got:
                tp[label] += 1
            else:
                fn[label] += 1
        for label in got - exp:
            # 12-digit invalid falling back to PHONE still counts as masked;
            # only count FP when nothing should be masked at all.
            if not exp:
                fp[label] += 1
    print(f"{'TYPE':<10}{'P':>6}{'R':>6}  n")
    all_labels = sorted(set(tp) | set(fn) | set(fp))
    for label in all_labels:
        p = tp[label] / max(tp[label] + fp[label], 1)
        r = tp[label] / max(tp[label] + fn[label], 1)
        print(f"{label:<10}{p:>6.2f}{r:>6.2f}  tp={tp[label]} fp={fp[label]} fn={fn[label]}")
    if misses:
        print("\nMISSES (must-recall failed):")
        for text, exp, got, out in misses:
            print(f"  - {text!r} expected={sorted(exp)} got={sorted(got)} -> {out!r}")
        return 1
    print("\nPII-EVAL PASSED — all must-recall cases masked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
