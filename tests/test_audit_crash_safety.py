"""Kill the gateway mid-request and prove the audit file survives.

The drain middleware claims a request interrupted between the provider
answering and the audit record being written is handled -- but that path was
only ever unit-tested against mocks. This kills a real process with SIGKILL,
which gives uvicorn no chance to run a shutdown handler at all, and then checks
the two things that would actually matter afterwards:

1. No torn record. SIGKILL can land between the write and the flush, so a
   partial final line is the failure mode worth fearing.
2. The chain still verifies. Records written before the kill must still chain,
   and a restart must be able to load the file at all.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.security.audit import load_verified_records  # noqa: E402
from aegis.security.auth import Authenticator  # noqa: E402

# The interpreter running the tests. Hardcoding `.venv/bin/python` works on a
# laptop and fails on CI, which has no venv -- it runs the system interpreter.
PYTHON = sys.executable
KEY = "torn-write-key-minimum-32-chars!!"
# No tenant exists by default, so an unauthenticated request would 401 and
# never reach the audit path -- the test would then pass by writing nothing.
TENANT_KEY = "hammer-key"
TENANTS = f"t1:{Authenticator.hash_key(TENANT_KEY)}:chat+rag"


def _start(tmp: Path, port: int) -> subprocess.Popen:
    env = {
        **os.environ,
        "AEGIS_AUDIT_HMAC_KEY": KEY,
        "AEGIS_AUDIT_PATH": str(tmp / "audit.jsonl"),
        "AEGIS_ADMIN_SESSION_KEY": "session-key-minimum-32-characters",
        "AEGIS_TENANTS": TENANTS,
    }
    proc = subprocess.Popen(
        [str(PYTHON), "-m", "uvicorn", "aegis.main:app", "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return proc
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    proc.kill()
    raise AssertionError("gateway did not start")


def _hammer(port: int, key: str) -> int:
    """Fire requests until one fails, which is what the kill looks like."""
    sent = 0
    for _ in range(400):
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat",
                data=json.dumps({"messages": [{"role": "user", "content": f"hello {sent}"}]}).encode(),
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10).read()
        except Exception:  # noqa: BLE001 — the kill is supposed to break this
            return sent
        sent += 1
    return sent


def test_sigkill_mid_request_leaves_no_torn_record(tmp_path, free_tcp_port):
    audit_file = tmp_path / "audit.jsonl"
    port = free_tcp_port
    proc = _start(tmp_path, port)

    import threading

    sent = {"n": 0}

    def fire():
        sent["n"] = _hammer(port, TENANT_KEY)

    worker = threading.Thread(target=fire, daemon=True)
    worker.start()
    time.sleep(1.0)

    # SIGKILL, not SIGTERM: no shutdown hook, no drain, no flush.
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait(timeout=10)
    worker.join(timeout=15)

    assert audit_file.exists(), "no audit file was written before the kill"
    raw = audit_file.read_text(encoding="utf-8")

    # 1. No torn final line.
    if raw and not raw.endswith("\n"):
        raise AssertionError("audit file ends mid-record: SIGKILL tore the final write")
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"line {number} is not valid JSON after a SIGKILL: {exc}") from exc

    # 2. Everything written before the kill is intact and chained.
    records = load_verified_records(audit_file, KEY)
    # A meaningful floor: passing on a single lucky write would prove nothing
    # about a kill landing mid-stream.
    assert len(records) >= 5, f"only {len(records)} record(s) before the kill; the test proved nothing"
    for previous, current in zip(records, records[1:], strict=False):
        assert current.prev_hash == previous.entry_hash, f"chain broken at seq {current.seq}"
    assert [r.seq for r in records] == sorted(r.seq for r in records), "sequence went backwards"
