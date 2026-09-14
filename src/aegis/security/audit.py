"""Hash-chained, HMAC-signed audit log.

Each record embeds the hash of the previous record; the chain head is signed.
Any tampering (edit, delete, reorder) breaks verification — tamper-evidence
required for regulated-industry AI deployments.

Format: JSONL, one record per line:
  {seq, ts, tenant, event, payload_sha256, prev_hash, entry_hash}
entry_hash = HMAC(key, seq|ts|tenant|event|payload_sha256|prev_hash)
"""

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl  # POSIX: cross-process file locks (multi-worker uvicorn)
except ImportError:  # Windows dev: in-process lock only
    fcntl = None  # type: ignore[no-redef,assignment]

log = logging.getLogger("aegis.audit")


class AuditError(Exception):
    pass


@dataclass
class AuditRecord:
    seq: int
    ts: float
    tenant: str
    event: str
    payload_sha256: str
    prev_hash: str
    entry_hash: str
    payload_enc: str | None = None
    payload_alg: str = "none"


def encrypt_payload(payload_bytes: bytes, key: str) -> tuple[str | None, str]:
    """Encrypt audit payload for at-rest evidence. Returns (cipher, alg).

    Fernet when `cryptography` is installed (alg=fernet, key derived via
    SHA-256 so any string works); else base64 envelope (alg=base64) so the
    JSONL export still carries the payload without blocking on new deps.
    Empty key disables encryption (None, none).
    """
    if not key:
        return None, "none"
    try:
        import base64 as _b64

        from cryptography.fernet import Fernet

        raw = hashlib.sha256(key.encode()).digest()
        fkey = _b64.urlsafe_b64encode(raw)
        token = Fernet(fkey).encrypt(payload_bytes).decode()
        return token, "fernet"
    except ImportError:
        import base64 as _b64

        return _b64.b64encode(payload_bytes).decode(), "base64"


def decrypt_payload(cipher: str, alg: str, key: str) -> bytes:
    import base64 as _b64

    if alg == "fernet":
        from cryptography.fernet import Fernet

        raw = hashlib.sha256(key.encode()).digest()
        return Fernet(_b64.urlsafe_b64encode(raw)).decrypt(cipher.encode())
    if alg == "base64":
        return _b64.b64decode(cipher.encode())
    raise AuditError(f"unknown payload_alg={alg}")


def archive_to_s3(path: Path, bucket: str, prefix: str = "aegis-audit/") -> str | None:
    """Best-effort upload of a rotated audit file. Returns s3:// URI or None."""
    if not bucket:
        return None
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError:
        log.warning("audit s3 archive skipped: boto3 not installed")
        return None
    try:
        key = f"{prefix.rstrip('/')}/{path.name}"
        boto3.client("s3").upload_file(str(path), bucket, key)
        return f"s3://{bucket}/{key}"
    except Exception as exc:  # noqa: BLE001 — archive never blocks serving
        log.warning("audit s3 archive failed: %s", exc)
        return None


class AuditChain:
    def __init__(self, hmac_key: str, path: str = "audit.jsonl", max_bytes: int = 10_000_000,
                 encrypt_key: str = "", s3_bucket: str = "", s3_prefix: str = "aegis-audit/") -> None:
        self._key = hmac_key.encode()
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.encrypt_key = encrypt_key
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix
        self.seq = 0
        self.head = "GENESIS"
        self._thread_lock = threading.Lock()
        self._load()

    @contextmanager
    def _locked(self, exclusive: bool):
        """In-process mutex + POSIX flock so N uvicorn workers sharing one
        file never mint duplicate seq or fork prev_hash. Best-effort on
        platforms without fcntl (lock degrades to in-process)."""
        with self._thread_lock:
            if fcntl is None:  # non-POSIX: in-process mutex only
                yield
                return
            lock_path = self.path.with_suffix(self.path.suffix + ".lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with lock_path.open("w", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                try:
                    yield
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _read_tail(self) -> AuditRecord | None:
        """Last record in the file without loading it all (O(tail))."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return None
        if size == 0:
            return None
        with self.path.open("rb") as fh:
            # walk back until we hold at least two newlines (one full line)
            step, buf = 4096, b""
            pos = size
            while pos > 0 and buf.count(b"\n") < 2:
                pos = max(0, pos - step)
                fh.seek(pos)
                buf = fh.read(size - pos)
                if pos == 0:
                    break
        lines = [ln for ln in buf.decode("utf-8", "replace").splitlines() if ln.strip()]
        if not lines:
            return None
        raw = json.loads(lines[-1])
        raw.setdefault("payload_enc", None)
        raw.setdefault("payload_alg", "none")
        return AuditRecord(**{k: raw[k] for k in AuditRecord.__dataclass_fields__})

    def _refresh_from_tail(self) -> None:
        """Adopt newer seq/head written by a sibling worker. Only advances —
        never rewinds past a rotation this process performed itself."""
        tail = self._read_tail()
        if tail is not None and tail.seq > self.seq:
            self.seq = tail.seq
            self.head = tail.entry_hash

    # -- internals ----------------------------------------------------------

    def _entry_hash(self, seq: int, ts: float, tenant: str, event: str,
                    payload_sha256: str, prev_hash: str) -> str:
        material = f"{seq}|{ts:.6f}|{tenant}|{event}|{payload_sha256}|{prev_hash}"
        return hmac.new(self._key, material.encode(), hashlib.sha256).hexdigest()

    def _load(self) -> None:
        if not self.path.exists():
            return
        last: AuditRecord | None = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                # backward-compat: old lines lack payload_enc/payload_alg
                raw.setdefault("payload_enc", None)
                raw.setdefault("payload_alg", "none")
                rec = AuditRecord(**{k: raw[k] for k in AuditRecord.__dataclass_fields__})
                expected = self._entry_hash(rec.seq, rec.ts, rec.tenant, rec.event,
                                            rec.payload_sha256, rec.prev_hash)
                if not hmac.compare_digest(expected, rec.entry_hash):
                    raise AuditError(f"audit chain corrupt at seq={rec.seq}")
                if last is not None and rec.prev_hash != last.entry_hash:
                    raise AuditError(f"audit chain broken linkage at seq={rec.seq}")
                last = rec
        if last is not None:
            self.seq = last.seq
            self.head = last.entry_hash

    # -- public ---------------------------------------------------------------

    def _maybe_rotate(self) -> None:
        """Rotate when over budget, carrying head into the new file.

        New file's first record uses prev_hash=old head, so per-file verify()
        holds and cross-file continuity is checkable by matching heads.
        Best-effort: rotation failure never blocks the request path.
        Must run under the exclusive lock (append holds it).
        """
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                backup = self.path.with_suffix(self.path.suffix + ".1")
                if backup.exists():
                    backup.unlink()
                self.path.rename(backup)
                uri = archive_to_s3(backup, self.s3_bucket, self.s3_prefix)
                if uri:
                    log.info("audit rotated, archived %s", uri)
        except OSError:
            pass

    def append(self, tenant: str, event: str, payload: dict) -> AuditRecord:
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        payload_enc, payload_alg = encrypt_payload(payload_bytes, self.encrypt_key)
        with self._locked(exclusive=True):
            # adopt seq/head minted by sibling workers, then rotate, then write —
            # all atomically, so multi-worker uvicorn can't fork the chain.
            self._refresh_from_tail()
            self._maybe_rotate()
            ts = time.time()
            self.seq += 1
            entry_hash = self._entry_hash(self.seq, ts, tenant, event, payload_sha256, self.head)
            record = AuditRecord(
                seq=self.seq,
                ts=ts,
                tenant=tenant,
                event=event,
                payload_sha256=payload_sha256,
                prev_hash=self.head,
                entry_hash=entry_hash,
                payload_enc=payload_enc,
                payload_alg=payload_alg,
            )
            line = json.dumps(record.__dict__, separators=(",", ":"))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.head = entry_hash
            return record

    def verify(self) -> tuple[bool, str]:
        try:
            with self._locked(exclusive=False):
                self._load()
            return True, f"chain intact, head={self.head[:12]}…, length={self.seq}"
        except AuditError as exc:
            return False, str(exc)
