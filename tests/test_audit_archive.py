"""The S3 archive path, both directions.

`AEGIS_AUDIT_S3_BUCKET` was documented in the config, the runbook and ADR-7,
and `archive_to_s3` imported boto3 -- but boto3 was not in any dependency extra,
so setting the variable logged a warning and did nothing. There was also no test
on the path at all, and no way to bring an archived segment back.

These use a stub client rather than real object storage: the behaviour under test
is *what we ask S3 for and what we accept back*, and a fake keeps that testable
without network or credentials. Anything asserting real S3 semantics would be
testing boto3, not this code.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from aegis.security.audit import AuditChain, FleetLedger, archive_to_s3, fetch_s3_segments

KEY = "archive-round-trip-key-minimum!!"


class _StubClient:
    """Records calls and serves objects from an in-memory bucket."""

    def __init__(self, objects: dict[str, bytes] | None = None, fail: bool = False, pages: int = 1):
        self.objects = objects or {}
        self.fail = fail
        self.pages = pages
        self.uploads: list[tuple[str, str, str]] = []
        self.downloads: list[tuple[str, str, str]] = []

    def upload_file(self, source: str, bucket: str, key: str) -> None:
        if self.fail:
            raise RuntimeError("network down")
        self.uploads.append((source, bucket, key))
        self.objects[key] = open(source, "rb").read()

    def download_file(self, bucket: str, key: str, target: str) -> None:
        if self.fail:
            raise RuntimeError("network down")
        self.downloads.append((bucket, key, target))
        with open(target, "wb") as fh:
            fh.write(self.objects[key])

    def list_objects_v2(self, Bucket, Prefix, **kwargs):  # noqa: N803 — boto3's casing
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        if kwargs.get("ContinuationToken") == "page-2":
            return {"Contents": [{"Key": k} for k in keys[1:]], "IsTruncated": False}
        if self.pages > 1:
            return {
                "Contents": [{"Key": keys[0]}] if keys else [],
                "IsTruncated": True,
                "NextContinuationToken": "page-2",
            }
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}


@pytest.fixture()
def stub_boto3(monkeypatch):
    """Install a fake `boto3` module, since it is an optional dependency."""
    holder: dict[str, _StubClient] = {}

    def install(client: _StubClient) -> _StubClient:
        module = types.ModuleType("boto3")
        module.client = lambda _service, **_kw: client  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "boto3", module)
        holder["client"] = client
        return client

    install._holder = holder  # type: ignore[attr-defined]
    return install


def _write_segment(directory, name, count, key=KEY):
    chain = AuditChain(path=directory / name, hmac_key=key, max_bytes=10**9)
    for i in range(count):
        chain.append("t", "probe", {"i": i})
    return directory / name


def test_archive_is_a_no_op_without_a_bucket(tmp_path):
    segment = _write_segment(tmp_path, "audit.jsonl", 2)
    assert archive_to_s3(segment, bucket="") is None


def test_archive_uploads_to_the_configured_prefix(tmp_path, stub_boto3):
    segment = _write_segment(tmp_path, "audit.jsonl", 2)
    client = stub_boto3(_StubClient())
    uri = archive_to_s3(segment, bucket="aegis-logs", prefix="aegis-audit/")
    assert uri == "s3://aegis-logs/aegis-audit/audit.jsonl"
    assert client.uploads == [(str(segment), "aegis-logs", "aegis-audit/audit.jsonl")]


def test_a_failed_upload_returns_none_rather_than_raising(tmp_path, stub_boto3):
    segment = _write_segment(tmp_path, "audit.jsonl", 2)
    stub_boto3(_StubClient(fail=True))
    assert archive_to_s3(segment, bucket="aegis-logs") is None


def test_fetch_round_trips_an_archived_segment(tmp_path, stub_boto3):
    """The whole point: a pruned host can get its own history back."""
    source = tmp_path / "src"
    source.mkdir()
    segment = _write_segment(source, "audit.jsonl", 3)
    stub_boto3(_StubClient())
    archive_to_s3(segment, bucket="aegis-logs")

    cache = tmp_path / "cache"
    fetched = fetch_s3_segments("aegis-logs", cache, "aegis-audit/", KEY)
    assert [p.name for p in fetched] == ["audit.jsonl"]
    from aegis.security.audit import load_verified_records

    assert len(load_verified_records(fetched[0], KEY)) == 3


def test_fetch_ignores_objects_that_are_not_segments(tmp_path, stub_boto3):
    """A shared prefix may hold other things; only segments are ledger."""
    stub_boto3(
        _StubClient(
            {
                "aegis-audit/audit.jsonl.1": b"",
                "aegis-audit/README.txt": b"not a segment",
                "aegis-audit/config.json": b"{}",
                "aegis-audit/audit.jsonl.gz": b"",
                "other/audit.jsonl.9": b"",
            }
        )
    )
    fetched = fetch_s3_segments("b", tmp_path / "cache", "aegis-audit/", KEY)
    assert [p.name for p in fetched] == ["audit.jsonl.1"], f"pulled in the wrong objects: {[p.name for p in fetched]}"


def test_fetch_rejects_a_forged_object(tmp_path, stub_boto3):
    """Archive objects are untrusted input until they verify."""
    from aegis.security.audit import AuditChain as _AC

    good = tmp_path / "src"
    good.mkdir()
    segment = _write_segment(good, "audit.jsonl", 2)
    client = stub_boto3(_StubClient())
    archive_to_s3(segment, bucket="b")

    forged = json.loads((segment).read_text().splitlines()[0])
    forged["event"] = "forged"
    client.objects["aegis-audit/audit.jsonl"] = (json.dumps(forged) + "\n").encode()

    fetched = fetch_s3_segments("b", tmp_path / "cache", "aegis-audit/", KEY)
    assert fetched == [], "an object that does not verify must not enter the ledger"
    assert _AC is not None


def test_fetch_follows_pagination(tmp_path, stub_boto3):
    objects = {"aegis-audit/audit.jsonl.2": b"", "aegis-audit/audit.jsonl.1": b""}
    stub_boto3(_StubClient(objects, pages=2))
    fetched = fetch_s3_segments("b", tmp_path / "cache", "aegis-audit/")
    assert [p.name for p in fetched] == ["audit.jsonl.1", "audit.jsonl.2"]


def test_fetch_without_a_bucket_is_a_no_op(tmp_path):
    assert fetch_s3_segments("", tmp_path / "cache") == []


def test_fetch_failure_does_not_raise(tmp_path, stub_boto3):
    """A ledger must still reconcile what it has when storage is unreachable."""
    stub_boto3(_StubClient(fail=True))
    assert fetch_s3_segments("b", tmp_path / "cache", "aegis-audit/", KEY) == []


def test_ledger_sync_pulls_archived_segments_in(tmp_path, stub_boto3):
    source = tmp_path / "src"
    source.mkdir()
    segment = _write_segment(source, "audit.jsonl.1", 2)
    client = stub_boto3(_StubClient())
    archive_to_s3(segment, bucket="b")

    live = tmp_path / "live"
    live.mkdir()
    local = _write_segment(live, "audit.jsonl", 2)

    ledger = FleetLedger(local, KEY, s3_bucket="b", archive_cache=tmp_path / "cache")
    before = ledger.status()
    assert before["records"] == 2, "only the live file before the sync"

    ledger.sync_from_archive()
    after = ledger.status(refresh=True)
    assert after["records"] == 4, "the archived segment must be counted after a sync"
    assert client.downloads, "nothing was actually fetched"


def test_ledger_sync_is_a_no_op_without_a_bucket(tmp_path):
    live = tmp_path / "live"
    live.mkdir()
    local = _write_segment(live, "audit.jsonl", 1)
    assert FleetLedger(local, KEY).sync_from_archive() == []
