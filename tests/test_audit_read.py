"""The audit trail has to be *readable*, not merely verifiable.

`verify()` returning "chain intact" is a boolean you have to take on faith. The
product claim is "prove what the AI said", which means an operator must be able
to pull the records back, see them re-verified row by row, and read the payload
that the signature covers. These tests pin that contract, including the cases
where the honest answer is "this row is broken".
"""

import json

import pytest

from aegis.security.audit import MAX_READ_RECORDS, AuditChain, AuditError

KEY = "test-audit-key-32-chars-minimum!!"


def make_chain(tmp_path, **kwargs):
    return AuditChain(KEY, path=str(tmp_path / "audit.jsonl"), **kwargs)


def reader_for(path, **kwargs):
    """A read-only handle on a file whose chain is known to be broken.

    `AuditChain.__init__` verifies the whole file and refuses to load a corrupt
    one — correct for the serving path (never answer from a chain you can't
    trust) but useless for the operator who is investigating the corruption.
    Pointing an already-constructed chain at the damaged file gives that handle.
    """
    chain = AuditChain(KEY, path=str(path.with_suffix(".unused.jsonl")), **kwargs)
    chain.path = path
    return chain


def test_tail_records_returns_newest_window_oldest_first(tmp_path):
    chain = make_chain(tmp_path)
    for i in range(10):
        chain.append("acme", "chat_completed", {"i": i})

    data = chain.tail_records(limit=3)
    assert [r["seq"] for r in data["records"]] == [8, 9, 10]
    assert data["count"] == 3
    assert data["all_signatures_valid"] is True


def test_every_row_is_individually_reverified(tmp_path):
    chain = make_chain(tmp_path)
    for i in range(5):
        chain.append("acme", "event", {"i": i})

    data = chain.tail_records(limit=5)
    assert all(r["sig_ok"] for r in data["records"])
    # The oldest row in a full-file window is anchored to GENESIS, so its link
    # is checkable rather than unknown.
    assert data["window_reached_start"] is True
    assert data["records"][0]["link_ok"] is True
    assert all(r["link_ok"] for r in data["records"])


def test_deleted_middle_record_reports_broken_link_not_silence(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(KEY, path=str(path))
    for i in range(4):
        chain.append("acme", "event", {"i": i})

    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditError):
        AuditChain(KEY, path=str(path))  # serving path still refuses to load it

    # Reading must not raise — a broken chain is the finding, not an exception
    # that hides the evidence.
    data = reader_for(path).tail_records(limit=10)
    assert data["all_links_valid"] is False
    broken = [r for r in data["records"] if r["link_ok"] is False]
    assert len(broken) == 1
    assert broken[0]["seq"] == 3  # the row whose prev_hash no longer matches


def test_edited_row_fails_signature_check(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(KEY, path=str(path))
    chain.append("acme", "chat_completed", {"n": 1})
    chain.append("acme", "chat_completed", {"n": 2})

    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["event"] = "forged_event"
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    data = reader_for(path).tail_records(limit=10)
    assert data["all_signatures_valid"] is False
    assert data["records"][0]["sig_ok"] is False
    assert data["records"][1]["sig_ok"] is True


def test_request_id_is_signed_not_decorative(tmp_path):
    """The correlation column must be inside the HMAC, or it is forgeable."""
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(KEY, path=str(path))
    chain.append("acme", "chat_completed", {"n": 1}, request_id="rid-abc")

    data = chain.tail_records(limit=1)
    assert data["records"][0]["request_id"] == "rid-abc"
    assert data["records"][0]["sig_ok"] is True

    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["request_id"] = "rid-forged"
    path.write_text(json.dumps(rec) + "\n")

    tampered = reader_for(path).tail_records(limit=1)
    assert tampered["records"][0]["sig_ok"] is False, "request_id must be covered by the signature"


def test_pre_request_id_chains_still_verify(tmp_path):
    """Adding a correlation column must not invalidate history."""
    path = tmp_path / "audit.jsonl"
    legacy = AuditChain(KEY, path=str(path))
    ts = 1_700_000_000.0
    entry = legacy._entry_hash(1, ts, "acme", "chat_completed", "deadbeef", "GENESIS")
    path.write_text(json.dumps({
        "seq": 1, "ts": ts, "tenant": "acme", "event": "chat_completed",
        "payload_sha256": "deadbeef", "prev_hash": "GENESIS", "entry_hash": entry,
    }) + "\n")

    data = AuditChain(KEY, path=str(path)).tail_records(limit=1)
    assert data["records"][0]["sig_ok"] is True
    assert data["records"][0]["request_id"] == ""
    # no payload copy existed in the old format — reported, not invented
    assert data["records"][0]["payload"] is None


def test_payload_is_decrypted_and_tied_to_the_signed_digest(tmp_path):
    chain = make_chain(tmp_path, encrypt_key="evidence-key")
    chain.append("acme", "chat_completed", {"model": "echo-economy", "in_tokens": 7})

    data = chain.tail_records(limit=1)
    row = data["records"][0]
    assert data["payload_available"] is True
    assert row["payload"]["model"] == "echo-economy"
    assert row["payload_ok"] is True


def test_swapped_payload_cipher_is_caught(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(KEY, path=str(path), encrypt_key="evidence-key")
    chain.append("acme", "chat_completed", {"model": "echo-economy"})
    chain.append("acme", "chat_completed", {"model": "echo-premium"})

    lines = path.read_text().splitlines()
    first, second = json.loads(lines[0]), json.loads(lines[1])
    first["payload_enc"] = second["payload_enc"]  # move a genuine cipher between rows
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n")

    data = reader_for(path, encrypt_key="evidence-key").tail_records(limit=2)
    assert data["records"][0]["payload_ok"] is False, (
        "sha256(decrypted) must equal the signed payload_sha256"
    )
    assert data["records"][1]["payload_ok"] is True


def test_payloads_absent_when_encryption_disabled(tmp_path):
    chain = make_chain(tmp_path)
    chain.append("acme", "chat_completed", {"secret": "value"})
    data = chain.tail_records(limit=1)
    assert data["payload_available"] is False
    assert data["records"][0]["payload"] is None
    assert data["records"][0]["payload_ok"] is None


def test_filters_by_tenant_and_event(tmp_path):
    chain = make_chain(tmp_path)
    chain.append("acme", "chat_completed", {"n": 1})
    chain.append("globex", "chat_completed", {"n": 2})
    chain.append("acme", "injection_blocked", {"n": 3})
    chain.append("acme", "chat_completed", {"n": 4})

    assert [r["seq"] for r in chain.tail_records(tenant="acme")["records"]] == [1, 3, 4]
    assert [r["seq"] for r in chain.tail_records(event="injection_blocked")["records"]] == [3]
    both = chain.tail_records(tenant="acme", event="chat_completed")
    assert [r["seq"] for r in both["records"]] == [1, 4]


def test_anchor_row_verifies_the_oldest_returned_record(tmp_path):
    """Reading one row beyond the window is what makes the oldest returned row
    checkable. Without the anchor its `prev_hash` points at a row we never read,
    and the honest answer would have to be "unknown"."""
    chain = make_chain(tmp_path)
    for i in range(MAX_READ_RECORDS + 40):
        chain.append("acme", "event", {"i": i})

    data = chain.tail_records(limit=10)
    assert data["window_reached_start"] is False
    assert data["truncated"] is True
    assert data["records"][0]["seq"] == MAX_READ_RECORDS + 31
    assert data["records"][0]["link_ok"] is True, "the anchor row supplied the link"
    assert data["all_links_valid"] is True


def test_no_anchor_left_at_the_limit_boundary_is_reported_as_unknown(tmp_path):
    """At the hard ceiling there is no room for an anchor, so the oldest row's
    link is reported as unknown rather than asserted true."""
    chain = make_chain(tmp_path)
    for i in range(MAX_READ_RECORDS + 40):
        chain.append("acme", "event", {"i": i})

    data = chain.tail_records(limit=MAX_READ_RECORDS)
    assert data["window_reached_start"] is False
    assert data["records"][0]["link_ok"] is None
    assert data["all_links_valid"] is True  # None is "unknown", not "failed"


def test_limit_is_bounded(tmp_path):
    chain = make_chain(tmp_path)
    chain.append("acme", "event", {})
    data = chain.tail_records(limit=10_000_000)
    assert data["count"] == 1  # clamped, and only one record exists


def test_reverse_reader_spans_block_boundaries(tmp_path):
    """>64 KB of records must still be read back exactly, newest first."""
    chain = make_chain(tmp_path)
    pad = "x" * 400
    for i in range(400):
        chain.append("acme", "event", {"i": i, "pad": pad})

    data = chain.tail_records(limit=50)
    assert [r["seq"] for r in data["records"]] == list(range(351, 401))
    assert data["all_signatures_valid"] is True
    assert data["records"][0]["prev_hash"] == data["records"][0]["prev_hash"].lower()


def test_malformed_line_is_surfaced(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(KEY, path=str(path))
    chain.append("acme", "event", {"n": 1})
    with path.open("a", encoding="utf-8") as fh:
        fh.write("{not json at all\n")

    data = chain.tail_records(limit=5)
    assert data["malformed"] and "JSONDecodeError" in data["malformed"][0]["error"]
    assert data["count"] == 1  # the good row is still returned


def test_missing_file_reads_empty(tmp_path):
    data = AuditChain(KEY, path=str(tmp_path / "nothing.jsonl")).tail_records(limit=5)
    assert data["records"] == []
    assert data["chain"]["length"] == 0


def test_read_does_not_disturb_the_chain(tmp_path):
    chain = make_chain(tmp_path)
    for i in range(3):
        chain.append("acme", "event", {"i": i})
    head_before, seq_before = chain.head, chain.seq

    chain.tail_records(limit=10)
    chain.append("acme", "event", {"i": 99})

    assert chain.seq == seq_before + 1
    assert chain.head != head_before
    ok, msg = chain.verify()
    assert ok and "length=4" in msg


@pytest.mark.parametrize("limit", [1, 2, 500])
def test_limit_edges(tmp_path, limit):
    chain = make_chain(tmp_path)
    for i in range(5):
        chain.append("acme", "event", {"i": i})
    data = chain.tail_records(limit=limit)
    assert data["count"] == min(limit, 5)
    assert data["records"][-1]["seq"] == 5
