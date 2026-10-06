"""Time-based retention prunes only what object storage already holds.

Count-based retention answers "how many"; age-based answers "how old". Both
gates share one invariant: the archived gate applies to each. An old segment
with no other copy is evidence, not garbage, so it stays.
"""

from __future__ import annotations

import os
import pathlib
import time

from aegis.security.audit import AuditChain, discover_segments

KEY = "retention-key"
OLD = time.time() - 30 * 86400


def _ledger(tmp_path: pathlib.Path, count: int = 8) -> tuple[AuditChain, pathlib.Path]:
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=200, keep_days=7)
    for i in range(count):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    return chain, base


def _age_all(path: pathlib.Path, mtime: float) -> None:
    for seg in discover_segments(path):
        os.utime(seg, (mtime, mtime))


def test_disabled_by_default(tmp_path: pathlib.Path):
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=200)
    for i in range(8):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    for seg in discover_segments(base):
        chain._archived.add(seg.name)
        os.utime(seg, (OLD, OLD))
    chain._prune_archived()
    total = sum(sum(1 for _ in p.open(encoding="utf-8")) for p in discover_segments(base))
    assert total == 8, "keep_days=0 must never prune by age"


def test_old_archived_segments_pruned(tmp_path: pathlib.Path):
    chain, base = _ledger(tmp_path)
    segments = [p for p in discover_segments(base) if p.name != base.name]
    assert segments, "expected rotated segments"
    for seg in segments:
        chain._archived.add(seg.name)
    _age_all(base, OLD)
    # Live file is young again: age must never eat the file being written.
    os.utime(base, None)
    chain._prune_archived()
    remaining = [p.name for p in discover_segments(base)]
    assert base.name in remaining, "live file must survive age pruning"
    assert not (set(remaining) & {s.name for s in segments}), "old archived segments must go"


def test_old_unarchived_segments_kept(tmp_path: pathlib.Path):
    chain, base = _ledger(tmp_path)
    _age_all(base, OLD)
    os.utime(base, None)
    before = {p.name for p in discover_segments(base)}
    chain._prune_archived()
    assert {p.name for p in discover_segments(base)} == before, "no archive copy means no prune"


def test_young_archived_segments_kept(tmp_path: pathlib.Path):
    chain, base = _ledger(tmp_path)
    for seg in discover_segments(base):
        if seg.name != base.name:
            chain._archived.add(seg.name)
    before = {p.name for p in discover_segments(base)}
    chain._prune_archived()
    assert {p.name for p in discover_segments(base)} == before, "young segments stay regardless of archive"
