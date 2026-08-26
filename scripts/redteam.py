#!/usr/bin/env python3
"""Red-team harness: fires every attack in the corpus through the REAL gateway
pipeline (auth -> scan -> providers) and reports block rate. Exit 1 if any
attack leaks forbidden content — CI fails on security regressions.

Usage:
  python scripts/redteam.py --corpus scripts/attacks.yaml"""

import argparse
import asyncio
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.config import get_settings
from aegis.gateway import build_gateway


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="scripts/attacks.yaml")
    args = parser.parse_args()

    corpus = yaml.safe_load(Path(args.corpus).read_text(encoding="utf-8"))["attacks"]
    settings = get_settings()
    gateway = await build_gateway(settings)

    blocked_count = 0
    leaked = []
    print("=" * 64)
    print("  AEGIS RED-TEAM HARNESS")
    print("=" * 64)

    try:
        for atk in corpus:
            result = await gateway.handle_chat(
                tenant_id="redteam",
                messages=[{"role": "user", "content": atk["text"]}],
                max_tokens=200,
                use_cache=False,
            )
            answer_low = result["answer"].lower()

            leak_hits = [s for s in atk.get("must_not_leak", []) if s.lower() in answer_low]
            safe = result["blocked"] or not leak_hits
            if result["blocked"]:
                blocked_count += 1

            status = "BLOCKED" if result["blocked"] else ("DEFLECTED" if safe else "!! LEAK !!")
            labels = ",".join(result["injection"].get("labels", [])) or "-"
            print(f"  [{status:<10}] {atk['id']:<14} score={result['injection']['score']:<5} {labels}")
            if leak_hits:
                leaked.append((atk["id"], leak_hits))
                print(f"               LEAKED STRINGS: {leak_hits}")
    finally:
        await gateway.aclose()

    total = len(corpus)
    hard_blocked = blocked_count
    print("-" * 64)
    print(f"  attacks={total}  hard-blocked={hard_blocked}  "
          f"deflected={total - hard_blocked - len(leaked)}  leaked={len(leaked)}")

    if leaked:
        print("\nRED-TEAM FAILED — leaking attacks:")
        for atk_id, strs in leaked:
            print(f"  - {atk_id}: {strs}")
        return 1
    print("\nRED-TEAM PASSED — no forbidden content escaped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
