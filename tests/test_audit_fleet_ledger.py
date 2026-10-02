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
