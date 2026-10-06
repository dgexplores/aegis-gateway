"""Payload TTL: old encrypted copies go, hashes stay, purge audited.

Data minimization, not erasure — seq, hashes and linkage are retained, so the
chain still verifies. The purge appends its own record with the count, so an
operator can prove expiry happened rather than assert it.
"""

from __future__ import annotations

import json
import pathlib
import time

from aegis.security.audit import AuditChain

KEY = "purge-key"
ENC = "test-purge-encrypt-key"
OLD = 30 * 86400


def _old_chain(tmp_path: pathlib.Path, count: int = 4) -> tuple[AuditChain, pathlib.Path]:
    base = tmp_path / "audit.jsonl"
    now = time.time()
    import time as time_mod

    monkey_time = {"t": now - OLD}
    orig = time_mod.time
    time_mod.time = lambda: monkey_time["t"]  # restored in finally below
    try:
        chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9, encrypt_key=ENC)
        for i in range(count):
            chain.append("t", "chat_completed", {"i": i, "secret": "s3cr3t"})
    finally:
        time_mod.time = orig
    return chain, base


def test_old_payloads_purged_hashes_hold(tmp_path: pathlib.Path):
    chain, base = _old_chain(tmp_path)
    raws = [json.loads(line) for line in base.read_text(encoding="utf-8").splitlines()]
    assert all(r["payload_enc"] for r in raws), "setup must write real encrypted copies"

    purged = chain.purge_old_payloads(7)

    assert purged == 4
    raws = [json.loads(line) for line in base.read_text(encoding="utf-8").splitlines()]
    body = [r for r in raws if r["event"] == "chat_completed"]
    assert all(r["payload_enc"] is None and r["payload_alg"] == "none" for r in body)
    ok, detail = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9).verify()
    assert ok, detail
    purge_event = raws[-1]
    assert purge_event["event"] == "payload_purge", "expiry must itself be audited"


def test_young_payloads_kept(tmp_path: pathlib.Path):
    base = tmp_path / "audit.jsonl"
    chain = AuditChain(path=base, hmac_key=KEY, max_bytes=10**9, encrypt_key=ENC)
    chain.append("t", "chat_completed", {"i": 0})
    assert chain.purge_old_payloads(7) == 0
    raw = json.loads(base.read_text(encoding="utf-8").splitlines()[0])
    assert raw["payload_enc"] is not None


def test_disabled_by_default(tmp_path: pathlib.Path):
    chain, base = _old_chain(tmp_path)
    assert chain.purge_old_payloads(0) == 0
    assert chain.purge_old_payloads(-1) == 0
    total = sum(sum(1 for _ in p.open(encoding="utf-8")) for p in [base])
    assert total == 4
