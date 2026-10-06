"""Group commit keeps the chain whole while sharing one fsync per batch.

Batching must never weaken the guarantee: every record linked, seq contiguous,
ack only after the fsync. Correctness here is deterministic regardless of how
threads interleave, so no timing assertion — only the chain.
"""

from __future__ import annotations

import pathlib
import threading

from aegis.metrics import metrics
from aegis.security.audit import AuditChain

KEY = "batch-key"


def _hammer(chain: AuditChain, n: int, errors: list) -> None:
    try:
        for i in range(n):
            chain.append("t", "probe", {"i": i})
    except Exception as exc:  # noqa: BLE001 — collected, then asserted empty
        errors.append(exc)


def test_batched_appends_stay_linked(tmp_path: pathlib.Path):
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9, batch_window_ms=10)
    errors: list = []
    threads = [threading.Thread(target=_hammer, args=(chain, 10, errors)) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"batched appends raised: {errors[:3]}"
    ok, detail = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9).verify()
    assert ok, detail
    assert chain.seq == 200, f"lost records under batching: seq={chain.seq}"


def test_batch_reports_size(tmp_path: pathlib.Path):
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9, batch_window_ms=50)
    before_batches = metrics.total("aegis_audit_batch_total")
    before_size = metrics.total("aegis_audit_batch_size_total")
    errors: list = []
    threads = [threading.Thread(target=_hammer, args=(chain, 4, errors)) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert metrics.total("aegis_audit_batch_size_total") - before_size == 20
    assert metrics.total("aegis_audit_batch_total") - before_batches >= 1


def test_window_zero_stays_solo(tmp_path: pathlib.Path):
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9)
    before_batches = metrics.total("aegis_audit_batch_total")
    before_solo = metrics.total("aegis_audit_append_total")
    chain.append("t", "probe", {"i": 0})
    assert metrics.total("aegis_audit_append_total") - before_solo == 1
    assert metrics.total("aegis_audit_batch_total") == before_batches


def test_batch_error_reaches_followers(tmp_path: pathlib.Path):
    """A failed flush must wake every waiter with the cause, not hang them."""
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9, batch_window_ms=200)
    errors: list = []
    started = threading.Event()

    def waiter():
        started.set()
        try:
            chain.append("t", "probe", {"i": 1})
        except Exception as exc:  # noqa: BLE001 — the point: it raises, not hangs
            errors.append(exc)

    calls = {"n": 0}
    real_write = chain._write_batch

    def flaky(items):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk gone")
        return real_write(items)

    chain._write_batch = flaky  # type: ignore[method-assign]
    t = threading.Thread(target=waiter)
    t.start()
    assert started.wait(timeout=10)
    # Whoever leads the window flushes once and fails; the waiter in the same
    # window must get the same failure instead of hanging.
    try:
        chain.append("t", "probe", {"i": 0})
        raised_here = False
    except OSError:
        raised_here = True
    t.join(timeout=60)
    assert not t.is_alive(), "waiter hung instead of receiving the failure"
    assert raised_here and errors, "flush failure must reach every waiter"
    assert isinstance(errors[0], OSError)
