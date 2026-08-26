import json

import pytest

from aegis.security.audit import AuditChain, AuditError


def test_chain_appends_and_verifies(tmp_path):
    chain = AuditChain("secret-key-32-chars-minimum-ok!", path=str(tmp_path / "audit.jsonl"))
    for i in range(5):
        chain.append("t1", "event", {"i": i})
    ok, msg = chain.verify()
    assert ok
    assert "length=5" in msg


def test_tamper_detection_edit(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain("secret-key-32-chars-minimum-ok!", path=str(path))
    chain.append("t1", "event", {"n": 1})
    chain.append("t1", "event", {"n": 2})

    # tamper: edit the first line's event field
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["event"] = "forged"
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditError):
        AuditChain("secret-key-32-chars-minimum-ok!", path=str(path))


def test_tamper_detection_deletion(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain("secret-key-32-chars-minimum-ok!", path=str(path))
    chain.append("t1", "a", {"n": 1})
    chain.append("t1", "b", {"n": 2})
    chain.append("t1", "c", {"n": 3})

    lines = path.read_text().splitlines()
    del lines[1]  # remove middle record -> linkage breaks
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditError):
        AuditChain("secret-key-32-chars-minimum-ok!", path=str(path))


def test_wrong_key_fails_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditChain("key-one-32-chars-minimum-length!!", path=str(path)).append("t", "e", {})
    with pytest.raises(AuditError):
        AuditChain("key-two-32-chars-minimum-length!!", path=str(path))


def test_payload_hashed_not_stored(tmp_path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain("secret-key-32-chars-minimum-ok!", path=str(path))
    secret_payload = {"user_message": "my card is 4111111111111111"}
    chain.append("t1", "chat_completed", secret_payload)
    raw = path.read_text()
    assert "4111111111111111" not in raw  # only sha256 of payload is stored
