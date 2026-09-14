import json

from aegis.security.audit import AuditChain, archive_to_s3, decrypt_payload


def test_old_lines_still_verify(tmp_path):
    p = tmp_path / "audit.jsonl"
    chain = AuditChain("k", path=str(p))
    chain.append("t", "e", {"a": 1})
    # simulate legacy line: strip new keys
    raw = json.loads(p.read_text().strip().splitlines()[-1])
    raw.pop("payload_enc", None)
    raw.pop("payload_alg", None)
    p.write_text(json.dumps(raw) + "\n")
    chain2 = AuditChain("k", path=str(p))
    assert chain2.seq == 1
    ok, _ = chain2.verify()
    assert ok


def test_encrypt_roundtrip_base64(tmp_path):
    chain = AuditChain("k", path=str(tmp_path / "a.jsonl"), encrypt_key="secret")
    rec = chain.append("t", "chat_completed", {"model": "m"})
    assert rec.payload_enc
    raw = decrypt_payload(rec.payload_enc, rec.payload_alg, "secret")
    assert json.loads(raw)["model"] == "m"
    ok, _ = chain.verify()
    assert ok


def test_no_encrypt_by_default(tmp_path):
    chain = AuditChain("k", path=str(tmp_path / "a.jsonl"))
    rec = chain.append("t", "e", {"a": 1})
    assert rec.payload_enc is None
    assert rec.payload_alg == "none"


def test_s3_noop_without_bucket(tmp_path):
    p = tmp_path / "audit.jsonl.1"
    p.write_text("x\n")
    assert archive_to_s3(p, "") is None


def test_rotation_archives_best_effort(tmp_path, monkeypatch):
    import aegis.security.audit as mod
    called = {}
    monkeypatch.setattr(mod, "archive_to_s3",
                        lambda path, bucket, prefix="aegis-audit/": called.setdefault("uri", f"s3://{bucket}/x") or f"s3://{bucket}/x")
    p = tmp_path / "audit.jsonl"
    chain = AuditChain("k", path=str(p), max_bytes=10, s3_bucket="bkt")
    chain.append("t", "e", {"a": 1})
    chain.append("t", "e", {"a": 2})  # second append rotates first file -> archive
    assert called.get("uri") == "s3://bkt/x"
    ok, _ = chain.verify()
    assert ok
