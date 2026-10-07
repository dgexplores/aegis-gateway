"""Every audit append reports its own cost (Phase 1a).

Client wall-clock cannot separate server queueing from server work. These
counters can: lock-wait seconds vs hold seconds per append, as sums over a
count. A mean rising in lock-wait means threads queue at the audit lock; a
mean rising in hold means the disk got slow. Different fixes each.
"""

from __future__ import annotations

import pathlib

from aegis.metrics import metrics
from aegis.security.audit import AuditChain

KEY = "instrument-key"


def test_append_reports_lock_wait_and_hold(tmp_path: pathlib.Path):
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9)

    before_count = metrics.total("aegis_audit_append_total")
    before_wait = metrics.total("aegis_audit_lock_wait_seconds_total")
    before_hold = metrics.total("aegis_audit_append_seconds_total")

    for i in range(5):
        chain.append("t", "probe", {"i": i})

    assert metrics.total("aegis_audit_append_total") - before_count == 5
    wait = metrics.total("aegis_audit_lock_wait_seconds_total") - before_wait
    hold = metrics.total("aegis_audit_append_seconds_total") - before_hold
    assert wait >= 0, "lock wait cannot be negative"
    assert hold > 0, "hold must include a real write + fsync"
    assert hold / 5 < 1.0, "mean append hold above a second means the disk stalled"


def test_counters_survive_rotation(tmp_path: pathlib.Path):
    """Rotation must not swallow the report: the inc runs after append."""
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=200)

    before = metrics.total("aegis_audit_append_total")
    for i in range(10):
        chain.append("t", "probe", {"i": i, "pad": "x" * 60})
    assert metrics.total("aegis_audit_append_total") - before == 10
