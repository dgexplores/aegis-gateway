"""The global ledger: segments, assembly, and continuity (M12).

Each test here corresponds to a way the ledger was previously able to look
healthy while records were missing, or to silently destroy records outright.
"""

from __future__ import annotations

import pathlib

import pytest

from aegis.security.audit import AuditChain, FleetLedger, discover_segments, reconcile_segments

KEY = "fleet-key"


def _ledger(tmp_path: pathlib.Path, count: int = 40, max_bytes: int = 300) -> pathlib.Path:
    """A ledger that rotated on every append, so segment behaviour is visible."""
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=max_bytes)
    for i in range(count):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    return base


def test_rotation_never_destroys_an_earlier_segment(tmp_path):
    """Regression: rotation wrote to a single fixed `.1` and unlinked it first.

    The second rotation therefore deleted the previous segment. Sixty appends
    left two records on disk and nothing reported an error.
    """
    base = _ledger(tmp_path, count=60)
    segments = discover_segments(base)
    total = sum(sum(1 for _ in p.open(encoding="utf-8")) for p in segments)
    assert total == 60, "rotation must never drop records"


def test_segment_numbering_only_increases(tmp_path):
    base = _ledger(tmp_path, count=8)
    names = [p.name for p in discover_segments(base)]
    numbered = sorted(n for n in names if n != "audit.jsonl")
    assert numbered == [f"audit.jsonl.{i}" for i in range(1, len(numbered) + 1)]


def test_rotation_counter_survives_restart(tmp_path):
    """A restarted process must not reuse a segment number it already used."""
    base = _ledger(tmp_path, count=4)
    first = AuditChain(path=base, hmac_key=KEY, max_bytes=300)
    for i in range(4):
        first.append("t", "probe", {"i": i, "pad": "y" * 60})
    names = [p.name for p in discover_segments(base)]
    numbers = [int(n.rsplit(".", 1)[1]) for n in names if n != "audit.jsonl" and n.rsplit(".", 1)[1].isdigit()]
    assert len(numbers) == len(set(numbers)), "a segment number was reused after restart"


def test_discover_segments_includes_live_file_last(tmp_path):
    base = _ledger(tmp_path, count=6)
    found = discover_segments(base)
    assert found[-1].name == "audit.jsonl", "live file sorts last"
    assert ".lock" not in [p.name for p in found]


def test_chain_assembles_every_segment(tmp_path):
    """Regression: the chain walk stopped one step early.

    `chain.append(next_of[chain[-1]])` followed by `seen.add(next_of[chain[-1]])`
    read `chain[-1]` after the append, marking the segment two steps ahead, so
    every chain was truncated to two segments. No caller existed to notice.
    """
    base = _ledger(tmp_path, count=40)
    result = reconcile_segments(discover_segments(base), KEY)
    assert len(result["chains"]) == 1
    assert len(result["chains"][0]) == 40
    assert result["records"] == 40


def test_intact_ledger_reports_complete(tmp_path):
    base = _ledger(tmp_path, count=40)
    assert reconcile_segments(discover_segments(base), KEY)["complete"] is True


def test_lost_segment_is_reported_not_silently_split(tmp_path):
    """A lost segment breaks the hash link, which alone looks like a second pod."""
    base = _ledger(tmp_path, count=40)
    segments = discover_segments(base)
    segments[20].unlink()
    result = reconcile_segments(discover_segments(base), KEY)
    assert result["complete"] is False
    assert result["records"] == 39
    assert result["starts_mid_sequence"], "the orphaned chain must be named"
    assert result["starts_mid_sequence"][0]["missing_before"] == 21


def test_two_pods_are_not_reported_as_a_gap(tmp_path):
    """Separate chains are normal for a fleet; only a missing predecessor is not."""
    paths = []
    for pod in ("a", "b"):
        root = tmp_path / pod
        root.mkdir()
        chain = AuditChain(path=root / "audit.jsonl", hmac_key=KEY, max_bytes=300)
        for i in range(10):
            chain.append("t", "probe", {"i": i, "pad": f"{pod}{i}" * 10})
        paths.extend(discover_segments(root / "audit.jsonl"))
    result = reconcile_segments(paths, KEY)
    assert len(result["chains"]) == 2
    assert result["complete"] is True, "a two-pod fleet is not a continuity failure"


def test_tampered_segment_is_an_error_not_a_chain(tmp_path):
    base = _ledger(tmp_path, count=10)
    victim = sorted(discover_segments(base))[2]
    lines = victim.read_text(encoding="utf-8").splitlines()
    record = lines[0].replace('"probe"', '"tampered"')
    victim.write_text(record + "\n", encoding="utf-8")
    result = reconcile_segments(discover_segments(base), KEY)
    assert result["complete"] is False
    assert result["errors"]


def test_fleet_ledger_counts_every_segment(tmp_path):
    base = _ledger(tmp_path, count=40)
    status = FleetLedger(base, KEY).status()
    assert status["segments"] == 40
    assert status["records"] == 40
    assert status["longest_chain"] == 40
    assert status["complete"] is True


def test_fleet_ledger_caches_and_reports_age(tmp_path):
    base = _ledger(tmp_path, count=10)
    ledger = FleetLedger(base, KEY, ttl_seconds=60)
    first = ledger.status()
    second = ledger.status()
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["age_s"] >= 0


def test_fleet_ledger_detects_loss_on_refresh(tmp_path):
    base = _ledger(tmp_path, count=40)
    ledger = FleetLedger(base, KEY, ttl_seconds=60)
    assert ledger.status()["complete"] is True
    sorted(discover_segments(base))[20].unlink()
    assert ledger.status(refresh=True)["complete"] is False


def test_fleet_ledger_accepts_external_segments(tmp_path):
    """Segments restored from object storage are invisible to the local host."""
    base = _ledger(tmp_path, count=4)
    restored = tmp_path / "from_s3.jsonl"
    restored.write_text((tmp_path / "audit.jsonl.1").read_text(encoding="utf-8"), encoding="utf-8")
    status = FleetLedger(base, KEY, extra_paths=[restored]).status()
    assert status["segments"] == len(discover_segments(base)) + 1


@pytest.mark.parametrize("count", [1, 2, 5])
def test_short_ledgers_are_complete(tmp_path, count):
    base = _ledger(tmp_path, count=count)
    assert reconcile_segments(discover_segments(base), KEY)["complete"] is True


def _with_fake_archive(monkeypatch, succeed=True):
    """Pretend rotation archived to S3, so retention is permitted to act."""
    import aegis.security.audit as audit_mod

    def fake_archive(path, bucket, prefix="aegis-audit/"):
        return f"s3://bucket/{path.name}" if succeed else None

    monkeypatch.setattr(audit_mod, "archive_to_s3", fake_archive)


def test_retention_keeps_every_segment_by_default(tmp_path, monkeypatch):
    _with_fake_archive(monkeypatch)
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=300, s3_bucket="b", keep_segments=0)
    for i in range(12):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    assert len(discover_segments(base)) == 12, "keep_segments=0 must retain everything"


def test_retention_prunes_only_archived_segments(tmp_path, monkeypatch):
    _with_fake_archive(monkeypatch)
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=300, s3_bucket="b", keep_segments=3)
    for i in range(12):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    remaining = discover_segments(base)
    assert len(remaining) == 4, "three retained segments plus the live file"
    assert "audit.jsonl" in [p.name for p in remaining], "the live file is never pruned"


def test_retention_never_deletes_an_unarchived_segment(tmp_path, monkeypatch):
    """The whole point of the gate: no bucket configured means no deletion."""
    _with_fake_archive(monkeypatch, succeed=False)
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=300, keep_segments=2)
    for i in range(10):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    assert len(discover_segments(base)) == 10, "unarchived segments must survive"


def test_retention_warns_when_it_cannot_prune(tmp_path, monkeypatch, caplog):
    _with_fake_archive(monkeypatch, succeed=False)
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=300, keep_segments=2)
    with caplog.at_level("WARNING"):
        for i in range(8):
            chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    assert any("retention" in r.message for r in caplog.records), "unbounded growth must be surfaced"


def test_retention_sorts_segments_numerically(tmp_path, monkeypatch):
    """.10 must be treated as newer than .9, not older."""
    _with_fake_archive(monkeypatch)
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=300, s3_bucket="b", keep_segments=2)
    for i in range(30):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    kept = [p.name for p in discover_segments(base)]
    assert kept[:2] == ["audit.jsonl.28", "audit.jsonl.29"], f"kept the wrong segments: {kept[:3]}"


class _StubLedger:
    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises
        self.calls = 0

    def status(self, refresh=False):
        self.calls += 1
        if self._raises:
            raise self._raises
        return self._result


class _StubGateway:
    def __init__(self, ledger):
        self.audit_ledger = ledger
        self.audit_ledger.sync_from_archive = lambda: []


def _run_reconciler(ledger, ticks=3, interval=0.01):
    import asyncio
    import contextlib

    from aegis.api.routes import _audit_reconciler

    async def drive():
        task = asyncio.create_task(_audit_reconciler(_StubGateway(ledger), interval=interval))
        await asyncio.sleep(interval * (ticks + 1))
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(drive())


def test_reconciler_announces_a_ledger_that_is_not_whole(caplog):
    import logging

    ledger = _StubLedger(
        {
            "complete": False,
            "segments": 3,
            "records": 9,
            "errors": {},
            "seq_gaps": [],
            "starts_mid_sequence": [{"segment": "audit.jsonl.9"}],
        }
    )
    with caplog.at_level(logging.ERROR):
        _run_reconciler(ledger)
    assert any("not continuous" in r.message for r in caplog.records), (
        "a ledger that lost records must announce itself without an operator looking"
    )


def test_reconciler_stays_quiet_while_the_ledger_is_whole(caplog):
    import logging

    ledger = _StubLedger(
        {
            "complete": True,
            "segments": 3,
            "records": 9,
            "errors": {},
            "seq_gaps": [],
            "starts_mid_sequence": [],
        }
    )
    with caplog.at_level(logging.ERROR):
        _run_reconciler(ledger)
    assert not any("not continuous" in r.message for r in caplog.records)


def test_reconciler_survives_a_transient_failure(caplog):
    """A monitoring loop that dies on one bad poll stops monitoring forever."""
    import logging

    ledger = _StubLedger(raises=RuntimeError("volume hiccup"))
    with caplog.at_level(logging.WARNING):
        _run_reconciler(ledger)
    assert ledger.calls > 1, "the loop exited on the first exception"
    assert any("audit reconciliation failed" in r.message for r in caplog.records)


def test_reconciler_stops_cleanly_on_cancel():
    import asyncio
    import contextlib

    from aegis.api.routes import _audit_reconciler

    async def drive():
        task = asyncio.create_task(_audit_reconciler(_StubGateway(_StubLedger({"complete": True})), interval=0.01))
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert task.cancelled() or task.done()

    asyncio.run(drive())


def test_probe_does_not_reread_the_whole_chain(tmp_path, monkeypatch):
    """A liveness probe must stay O(1) as the ledger grows (M13).

    Measured: probe holds at ~0.05ms from 100 to 10,000 records while a full
    verify goes 0.38ms -> 31.7ms. A timing assertion would be flaky, so this
    pins the mechanism instead -- the probe must not re-verify the chain.
    """
    base = _ledger(tmp_path, count=50, max_bytes=10**9)
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9)

    reloaded = []
    monkeypatch.setattr(chain, "_load", lambda: reloaded.append(1))

    ok, detail = chain.probe()
    assert ok is True, detail
    assert not reloaded, "probe re-read the whole chain; its cost grows with chain length"


def test_probe_still_notices_a_corrupt_tail(tmp_path):
    """Cheap must not mean blind: a broken tail has to fail the probe.

    Constructed *before* the tamper, because `_load` at construction already
    rejects a corrupt chain -- the point here is what an already-running
    process reports once its file changes underneath it.
    """
    base = _ledger(tmp_path, count=6, max_bytes=10**9)
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9)

    raw = base.read_text(encoding="utf-8").splitlines()
    tampered = raw[-1].replace('"probe"', '"tampered"')
    base.write_text("\n".join(raw[:-1] + [tampered]) + "\n", encoding="utf-8")

    ok, detail = chain.probe()
    assert ok is False, "a corrupt tail must fail the probe"
    assert "corrupt" in detail
