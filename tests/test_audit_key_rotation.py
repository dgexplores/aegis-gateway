"""Rotating the audit HMAC key without destroying the evidence.

This is the item that decides whether the product is deployable on a normal
schedule. A signing key that cannot be rotated means either that you never
rotate it -- so a leaked key stays valid forever -- or that rotating it makes
every historical record unverifiable, which quietly deletes the evidence the
product exists to produce.

So: a chain accepts retired keys for verification while refusing to sign with
them. New records are signed with the current key; old records stay readable
under the key that signed them. The record format does not change, so a chain
written before any rotation still verifies byte-for-byte afterwards.

What rotation costs, stated plainly: if you drop a retired key from the list,
every record it signed stops verifying. That is the mechanism, not a bug, and
the tests below pin it so nobody discovers it during an audit.
"""

from __future__ import annotations

import pytest

from aegis.security.audit import AuditChain, AuditError, load_verified_records

KEY_A = "rotation-key-a-32-characters-min!!"
KEY_B = "rotation-key-b-32-characters-min!!"
KEY_C = "rotation-key-c-32-characters-min!!"


def write(path, key, n=25, tenant="acme"):
    chain = AuditChain(key, path=str(path))
    for i in range(n):
        chain.append(tenant, "event", {"i": i})
    return chain


def test_a_chain_written_under_one_key_verifies_under_it(tmp_path):
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A)
    ok, msg = AuditChain(KEY_A, path=str(path)).verify()
    assert ok, msg


def test_rotation_does_not_invalidate_history(tmp_path):
    """The whole point: a new key, and the old records still verify."""
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=10)

    # Rotate: B becomes current, A is retained for verification.
    rotated = AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A])
    ok, msg = rotated.verify()
    assert ok, f"rotation broke verification of existing records: {msg}"
    rotated.append("acme", "after_rotation", {"ok": True})

    assert AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A]).verify()[0]


def test_new_records_are_signed_with_the_current_key_only(tmp_path):
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=5)
    chain = AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A])
    chain.append("acme", "post_rotation", {"i": 99})

    rows = chain.tail_records(limit=50, with_payload=False)["records"]
    newest = rows[-1]
    assert newest["signed_with"] == "current"

    # A second rotation: C is current, A and B are history. Append under C --
    # without that, the newest record is still the one B signed, which is
    # history rather than current.
    second = AuditChain(KEY_C, path=str(path), hmac_previous_keys=[KEY_A, KEY_B])
    assert second.verify()[0]
    second.append("acme", "post_second_rotation", {"i": 100})
    rows = second.tail_records(limit=50, with_payload=False)["records"]
    assert rows[-1]["signed_with"] == "current"
    # ...and everything signed earlier still reads back.
    signed_with = {r["signed_with"] for r in rows}
    assert {"current", "previous:0", "previous:1"} <= signed_with, signed_with


def test_the_report_says_which_key_signed_each_record(tmp_path):
    """An operator has to be able to see that a rotation window is still open.

    If every record just says `sig_ok`, a key that has been retained for two
    years is indistinguishable from one retained for a week.
    """
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=3)
    chain = AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A])
    chain.append("acme", "post", {})

    rows = chain.tail_records(limit=50, with_payload=False)["records"]
    signed_with = [r["signed_with"] for r in rows]
    assert "current" in signed_with
    assert "previous:0" in signed_with


def test_dropping_a_retired_key_makes_its_records_unverifiable(tmp_path):
    """The cost of rotation, pinned.

    Records signed by a dropped key stop verifying. This is the correct
    behaviour -- the alternative is pretending a key never mattered -- but it is
    a real operational constraint: keep a retired key for at least as long as
    you might need to prove something it signed.
    """
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=5)

    with pytest.raises(AuditError):
        AuditChain(KEY_B, path=str(path))  # A not retained

    assert AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A]).verify()[0]


def test_an_unrelated_key_verifies_nothing(tmp_path):
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=5)
    with pytest.raises(AuditError):
        AuditChain(KEY_C, path=str(path), hmac_previous_keys=[KEY_C])


def test_a_tampered_record_is_still_caught_under_rotation(tmp_path):
    """Adding keys must not widen what counts as valid.

    The tempting failure is a verifier that accepts a record if *any* key
    matches without checking the others carefully, or that stops comparing
    entries once one matches. A record edited under key A must still fail while
    A is retained.
    """
    import json

    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=10)
    chain = AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A])
    chain.append("acme", "post", {"i": 10})

    lines = path.read_text().splitlines()
    record = json.loads(lines[3])
    record["payload_sha256"] = "0" * 64
    lines[3] = json.dumps(record, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditError):
        AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A]).verify()


def test_the_standalone_loader_and_reconciler_honour_retired_keys(tmp_path):
    """The offline verifier is the one an auditor runs, so it must not be the
    one place rotation silently breaks."""
    from aegis.security.audit import reconcile_segments

    seg_a = tmp_path / "a.jsonl"
    write(seg_a, KEY_A, n=5)
    seg_b = tmp_path / "b.jsonl"
    AuditChain(KEY_B, path=str(seg_b), hmac_previous_keys=[KEY_A]).append("acme", "e", {})

    assert len(load_verified_records(seg_a, KEY_A)) == 5
    assert load_verified_records(seg_a, KEY_B, [KEY_A])
    with pytest.raises(AuditError):
        load_verified_records(seg_a, KEY_B)

    report = reconcile_segments([str(seg_a), str(seg_b)], KEY_B, [KEY_A])
    assert report["errors"] == {}, report
    assert report["records"] == 6, report

    # The same merge without the retired key must report the segment as corrupt
    # rather than silently merging a chain it could not verify.
    broken = reconcile_segments([str(seg_a), str(seg_b)], KEY_B)
    assert str(seg_a) in {k for k in broken["errors"]}, broken


def test_the_bootstrap_path_verifies_under_rotation(tmp_path):
    """`_load` runs at boot and raises rather than warning, so a wrong keyring
    must fail there — before the gateway serves anything."""
    path = tmp_path / "audit.jsonl"
    write(path, KEY_A, n=3)
    AuditChain(KEY_B, path=str(path), hmac_previous_keys=[KEY_A])  # boots fine
    with pytest.raises(AuditError):
        AuditChain(KEY_B, path=str(path))  # A dropped: refuses to boot
