"""Restore drill for the audit chain.

A backup you have never restored is a hypothesis. This is the smallest thing
that turns it into a fact, and it runs against the real `AuditChain` — same
verification code production uses on every read — rather than against a copy of
the file.

What it proves, and what it deliberately does not:

* **It proves** the archived chain still verifies end to end: every entry hash
  recomputes, every link matches its predecessor, and no record is missing.
* **It does not prove** disaster recovery. This copies a file; it does not
  restore a dead volume, replay a WAL, or stand up a database. Those need a real
  environment and a real outage. Do not read a green drill here as "we could
  recover from losing the pod".

    python scripts/restore_drill.py                 # drill on a fresh chain
    python scripts/restore_drill.py --from chain.jsonl   # drill a real archive
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

HMAC_KEY = "restore-drill-audit-hmac-key-32-chars!!!"


def build_chain(path: Path, records: int) -> None:
    from aegis.security.audit import AuditChain

    chain = AuditChain(HMAC_KEY, path=str(path))
    for i in range(records):
        chain.append("acme", "drill_event", {"i": i, "note": "restore drill payload"})


def drill(source: Path, workdir: Path, expect_head: str | None = None) -> int:
    from aegis.security.audit import AuditChain, AuditError

    # Restore the way you would in an incident: copy the archived file to its
    # operational path, then read it back through the same verification path a
    # /admin/audit request uses.
    restored = workdir / "audit.jsonl"
    shutil.copy2(source, restored)

    # A corrupt chain raises while loading rather than returning False, so this
    # is where a bad archive becomes a verdict. Without the catch, a drill run
    # during an actual incident prints a stack trace instead of telling anyone
    # whether their evidence is trustworthy.
    try:
        chain = AuditChain(HMAC_KEY, path=str(restored))
    except AuditError as exc:
        print(f"  source      {source}")
        print(f"  restored to {restored}")
        print(f"  load        FAILED — {exc}")
        print("\n  RESTORE DRILL FAILED — the archive does not verify. Do not trust it.",
              file=sys.stderr)
        return 1

    ok, detail = chain.verify()
    print(f"  source      {source}")
    print(f"  restored to {restored}")
    print(f"  records     {chain.seq}")
    print(f"  verify()    {'PASS' if ok else 'FAIL'} — {detail}")

    # The read path is the one operators actually use, so drill that too: it
    # re-verifies per row and reports the window, not just the file.
    read = chain.tail_records(limit=500)
    bad_sig = [r for r in read["records"] if not r.get("sig_ok")]
    bad_link = [r for r in read["records"] if r.get("link_ok") is False]
    print(f"  read-back   {read['count']} records, "
          f"{len(bad_sig)} bad signatures, {len(bad_link)} broken links, "
          f"all_signatures_valid={read.get('all_signatures_valid')}")

    if not ok or bad_sig or bad_link:
        print("\n  RESTORE DRILL FAILED — do not trust this archive.", file=sys.stderr)
        return 1

    # Tail loss is the one failure a chain cannot detect by itself: a file with
    # its last ten records deleted is still a perfectly valid, shorter chain. It
    # takes an anchor recorded when the records were written — which is what
    # `head` in the /admin/audit response and the S3 archive are for. Say so
    # rather than letting a green drill imply full coverage.
    if expect_head and chain.head != expect_head:
        print(f"\n  RESTORE DRILL FAILED — head is {chain.head!r}, expected {expect_head!r}. "
              "The chain is internally consistent, so this is tail loss.")
        return 1
    if not expect_head:
        print("\n  note: no --expect-head given, so tail loss is NOT covered by this run. "
              "A file cannot detect its own truncation — pass the head you recorded when "
              "the archive was written.")

    print("\n  RESTORE DRILL PASSED — the archive is intact and readable.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="source", help="an existing audit.jsonl to drill")
    ap.add_argument("--records", type=int, default=500)
    ap.add_argument("--expect-head", help="the chain head you expect, to detect tail loss")
    args = ap.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="aegis-restore-drill-"))
    source = Path(args.source) if args.source else workdir / "original.jsonl"

    if not args.source:
        build_chain(source, args.records)
        print(f"built a {args.records}-record chain and archived it")
    elif not source.exists():
        print(f"restore-drill: no such file: {source}", file=sys.stderr)
        return 2

    return drill(source, workdir, expect_head=args.expect_head)


if __name__ == "__main__":
    raise SystemExit(main())
