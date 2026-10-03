"""M12: reconciling per-pod audit chains must be mechanical, not manual.

Each pod keeps its own chain; rotation seals segments (with head carry-over)
and uploads them to S3. Reconciling N segments means: verify every record,
then order segments by head linkage. Segments sharing no link are different
pods — expected, not corruption.
"""

import json

from aegis.security.audit import AuditChain, reconcile_segments

KEY = "reconcile-key-32-chars-minimum!!"


def _pod_with_rotation(tmp_path, name, n, max_bytes=300):
    path = tmp_path / name
    chain = AuditChain(KEY, path=str(path), max_bytes=max_bytes)
    for i in range(n):
        chain.append("t1", "ev", {"i": i})
    files = sorted(p for p in tmp_path.glob(name + "*") if p.is_file() and p.suffix != ".lock")
    return [str(p) for p in files]


def test_linked_segments_order_into_one_chain(tmp_path):
    segs = _pod_with_rotation(tmp_path, "pod-a.jsonl", 8)
    # Rotation now numbers segments monotonically and retains every one. This
    # asserted `len(segs) == 2` until the fix, with a comment reading
    # "rotation keeps a single backup, so older generations are gone from
    # disk" -- the test was pinning the data-loss bug in place rather than
    # describing intended behaviour. At a 300-byte budget each record forces a
    # rotation, so eight appends leave eight segments and no lost records.
    assert len(segs) == 8, "rotation must retain every sealed segment"

    report = reconcile_segments(segs, KEY)

    assert report["errors"] == {}
    assert len(report["chains"]) == 1
    assert sorted(report["chains"][0]) == sorted(segs)
    on_disk = sum(len(open(p).read().splitlines()) for p in segs)
    assert report["records"] == on_disk == 8, "no append may be dropped"
    assert report["complete"] is True


def test_unlinked_segments_stay_separate_chains(tmp_path):
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    seg_a = _pod_with_rotation(dir_a, "pod.jsonl", 3, max_bytes=10**9)
    seg_b = _pod_with_rotation(dir_b, "pod.jsonl", 2, max_bytes=10**9)

    report = reconcile_segments(seg_a + seg_b, KEY)

    assert report["errors"] == {}
    assert len(report["chains"]) == 2
    assert report["records"] == 5


def test_tampered_segment_reported_not_merged(tmp_path):
    good = _pod_with_rotation(tmp_path, "good.jsonl", 3, max_bytes=10**9)
    bad_path = tmp_path / "bad.jsonl"
    AuditChain(KEY, path=str(bad_path)).append("t1", "ev", {"n": 1})
    lines = bad_path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["event"] = "forged"
    lines[0] = json.dumps(rec)
    bad_path.write_text("\n".join(lines) + "\n")

    report = reconcile_segments(good + [str(bad_path)], KEY)

    assert str(bad_path) in report["errors"]
    assert len(report["chains"]) == 1
    assert report["records"] == 3
