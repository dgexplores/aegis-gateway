"""Hash-chained, HMAC-signed audit log.

Each record embeds the hash of the previous record; the chain head is signed.
Any tampering (edit, delete, reorder) breaks verification — tamper-evidence
required for regulated-industry AI deployments.

Format: JSONL, one record per line:
  {seq, ts, tenant, event, payload_sha256, prev_hash, entry_hash, request_id}
entry_hash = HMAC(key, seq|ts|tenant|event|payload_sha256|prev_hash[|request_id])

`request_id` is signed too, but only when present, so chains written before the
field existed still verify byte-for-byte (their recomputed material is
unchanged). Without that, adding a correlation column would have invalidated
every historical chain.

`tail_records()` is the read side: it hands back the newest N records with each
signature and link re-checked and the encrypted payload decrypted, so the log is
not merely tamper-*evident* but actually *inspectable*.
"""

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl  # POSIX: cross-process file locks (multi-worker uvicorn)
except ImportError:  # Windows dev: in-process lock only
    fcntl = None  # type: ignore[no-redef,assignment]

log = logging.getLogger("aegis.audit")

# Upper bound on how many records a single read may return or scan. Evidence
# review needs a window, not the whole log — an unbounded read endpoint would
# turn "let me look at the audit trail" into an OOM on a busy tenant.
MAX_READ_RECORDS = 500


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
    request_id: str = ""


def payload_cipher_alg(key: str) -> str:
    """The algorithm `encrypt_payload` would actually use for this key.

    Reporting the *real* algorithm is the whole point. An operator who sets
    AEGIS_AUDIT_ENCRYPT_KEY needs to know whether their evidence is encrypted or
    merely encoded, and the answer depends on whether `cryptography` is
    installed — not on what the key looks like.
    """
    if not key:
        return "none"
    return "fernet" if fernet_available() else "base64"


def fernet_available() -> bool:
    try:
        import cryptography.fernet  # noqa: F401
    except ImportError:
        return False
    return True


def encrypt_payload(payload_bytes: bytes, key: str) -> tuple[str | None, str]:
    """Encrypt audit payload for at-rest evidence. Returns (cipher, alg).

    Fernet when `cryptography` is installed (alg=fernet, key derived via
    SHA-256 so any string works); else base64 envelope (alg=base64) so the
    JSONL export still carries the payload without blocking on new deps.
    Empty key disables encryption (None, none).

    The base64 fallback is *encoding, not encryption*: anyone who can read the
    audit file can read the payload. It exists so a payload copy still travels
    in the export, and it is labelled `base64` precisely so nothing mistakes it
    for ciphertext. Callers that need to promise encryption must check
    `payload_cipher_alg()` rather than assume a key implies fernet.
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


def _report_append(batched: bool, count: int, wait_s: float, hold_s: float) -> None:
    """One place for append cost counters, shared by the solo and batch paths."""
    from aegis.metrics import metrics

    prefix = "aegis_audit_batch" if batched else "aegis_audit_append"
    metrics.inc(f"{prefix}_total")
    if batched:
        metrics.inc(f"{prefix}_size_total", float(count))
    metrics.inc(f"{prefix}_lock_wait_seconds_total", wait_s)
    metrics.inc(f"{prefix}_seconds_total", hold_s)


class AuditChain:
    def __init__(
        self,
        hmac_key: str,
        path: str = "audit.jsonl",
        max_bytes: int = 10_000_000,
        encrypt_key: str = "",
        s3_bucket: str = "",
        s3_prefix: str = "aegis-audit/",
        keep_segments: int = 0,
        keep_days: float = 0,
        batch_window_ms: float = 0,
        hmac_previous_keys: Sequence[str] = (),
    ) -> None:
        # The signing key is `_keys[0]`. The rest are *accepted* for verification
        # only, and exist so a rotation does not invalidate the records the old
        # key signed. See `hmac_previous_keys` on the module for the rotation
        # procedure and what dropping a key costs.
        self._keys: list[bytes] = [hmac_key.encode()]
        for extra in hmac_previous_keys:
            if extra and extra != hmac_key and extra.encode() not in self._keys:
                self._keys.append(extra.encode())
        self._key = self._keys[0]
        self.path = Path(path)
        self._segment_no = self._highest_segment_on_disk() + 1
        self.max_bytes = max_bytes
        self.encrypt_key = encrypt_key
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix
        self.keep_segments = keep_segments
        self.keep_days = keep_days
        # Group-commit window in ms. 0 disables: every append fsyncs alone.
        # Above 0, threads arriving within one window share a single fsync
        # (leader-follower, no background thread). Ack still waits for the
        # fsync, so durability is identical — the trade is bounded latency
        # (one window) for throughput under concurrency.
        self.batch_window_ms = batch_window_ms
        self._batch_lock = threading.Lock()
        self._batch: list[dict] = []
        # Only segments confirmed in object storage may ever be pruned.
        self._archived: set[str] = set()
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
        raw.setdefault("request_id", "")
        return AuditRecord(**{k: raw[k] for k in AuditRecord.__dataclass_fields__})

    def _refresh_from_tail(self) -> None:
        """Adopt newer seq/head written by a sibling worker. Only advances —
        never rewinds past a rotation this process performed itself."""
        tail = self._read_tail()
        if tail is not None and tail.seq > self.seq:
            self.seq = tail.seq
            self.head = tail.entry_hash

    # -- internals ----------------------------------------------------------

    def _entry_hash(
        self, seq: int, ts: float, tenant: str, event: str, payload_sha256: str, prev_hash: str, request_id: str = ""
    ) -> str:
        """Signed material. `request_id` is appended only when non-empty so
        pre-existing records (which lack the field) still verify."""
        material = f"{seq}|{ts:.6f}|{tenant}|{event}|{payload_sha256}|{prev_hash}"
        if request_id:
            material = f"{material}|{request_id}"
        return hmac.new(self._key, material.encode(), hashlib.sha256).hexdigest()

    def _entry_hash_under(
        self,
        key: bytes,
        seq: int,
        ts: float,
        tenant: str,
        event: str,
        payload_sha256: str,
        prev_hash: str,
        request_id: str = "",
    ) -> str:
        material = f"{seq}|{ts:.6f}|{tenant}|{event}|{payload_sha256}|{prev_hash}"
        if request_id:
            material = f"{material}|{request_id}"
        return hmac.new(key, material.encode(), hashlib.sha256).hexdigest()

    def _verify_entry(self, rec: "AuditRecord") -> tuple[bool, int]:
        """Does this record's signature match under any accepted key?

        Returns ``(ok, key_slot)``. The slot is 0 for the current key and 1..n
        for the previous keys, so a caller can report *which* key a record was
        signed under — which is what tells an operator whether a rotation window
        is still open.

        Every candidate is compared even after a match, so the time does not
        depend on which key matched. With one key this is identical work to
        before, which matters because this is on the boot path.
        """
        matched = -1
        for slot, key in enumerate(self._keys):
            expected = self._entry_hash_under(
                key, rec.seq, rec.ts, rec.tenant, rec.event, rec.payload_sha256, rec.prev_hash, rec.request_id
            )
            if hmac.compare_digest(expected, rec.entry_hash):
                matched = slot
        return (matched >= 0), matched

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
                # backward-compat: old lines lack payload_enc/payload_alg/request_id
                raw.setdefault("payload_enc", None)
                raw.setdefault("payload_alg", "none")
                raw.setdefault("request_id", "")
                rec = AuditRecord(**{k: raw[k] for k in AuditRecord.__dataclass_fields__})
                ok, _slot = self._verify_entry(rec)
                if not ok:
                    raise AuditError(f"audit chain corrupt at seq={rec.seq}")
                if last is not None and rec.prev_hash != last.entry_hash:
                    raise AuditError(f"audit chain broken linkage at seq={rec.seq}")
                last = rec
        if last is not None:
            self.seq = last.seq
            self.head = last.entry_hash

    # -- public ---------------------------------------------------------------

    def _next_segment_path(self) -> Path:
        """First unused monotonically numbered segment path.

        Numbering only ever increases. An earlier version rotated to a single
        fixed ``.1`` backup and unlinked it first, so the second rotation
        silently destroyed the previous segment -- 60 appends at a 200-byte
        budget left 2 records on disk. An audit trail that deletes itself on a
        schedule is worse than no audit trail, because it still looks healthy.

        Cached because rotation runs on the request path under the exclusive
        lock: stat-ing every candidate each time made a long-lived process
        quadratic in its own segment count. The counter is re-derived from disk
        when a candidate is unexpectedly taken, which covers a restart or a
        restore that added segments underneath us.
        """
        for _ in range(2):
            candidate = self.path.with_suffix(self.path.suffix + f".{self._segment_no}")
            if not candidate.exists():
                self._segment_no += 1
                return candidate
            self._segment_no = self._highest_segment_on_disk() + 1
        candidate = self.path.with_suffix(self.path.suffix + f".{self._segment_no}")
        self._segment_no += 1
        return candidate

    def _prune_archived(self) -> None:
        """Drop the oldest segments once they are provably in object storage.

        Segments are now retained rather than overwritten, which turns the
        previous silent data loss into unbounded disk growth -- a real risk on a
        busy gateway, but only fixable by deletion, which is what caused the
        original bug. So deletion is gated on the segment having been uploaded:
        a segment that failed to archive, or was written while no bucket was
        configured, is kept and counted in the warning. Retention can never be
        the reason records disappear.
        """
        on_disk = [p.name for p in discover_segments(self.path) if p.name != self.path.name]
        if self.keep_segments > 0 and len(on_disk) > self.keep_segments:
            surplus = len(on_disk) - self.keep_segments
            removable = [name for name in sorted(on_disk, key=_segment_sort_key) if name in self._archived]
            for name in removable[:surplus]:
                try:
                    self.path.with_name(name).unlink()
                    self._archived.discard(name)
                    log.info("audit pruned %s (archived, over keep=%d)", name, self.keep_segments)
                except OSError:
                    continue
            kept = [n for n in on_disk if n not in removable[:surplus]]
            if len(kept) > self.keep_segments:
                log.warning(
                    "audit retention is %d segments over keep=%d: they are not archived, so they "
                    "are being kept. Set AEGIS_AUDIT_S3_BUCKET or the directory will grow without bound.",
                    len(kept) - self.keep_segments,
                    self.keep_segments,
                )
            on_disk = [p.name for p in discover_segments(self.path) if p.name != self.path.name]
        if self.keep_days > 0:
            # Age alone prunes, but the archived gate still applies: an old
            # segment that never reached object storage is evidence with no
            # other copy, so it stays and the operator gets told.
            cutoff = time.time() - self.keep_days * 86400
            for name in sorted(on_disk, key=_segment_sort_key):
                if name not in self._archived:
                    continue
                try:
                    if self.path.with_name(name).stat().st_mtime >= cutoff:
                        continue
                    self.path.with_name(name).unlink()
                    self._archived.discard(name)
                    log.info("audit pruned %s (archived, older than keep=%.1f days)", name, self.keep_days)
                except OSError:
                    continue

    def _highest_segment_on_disk(self) -> int:
        highest = 0
        prefix = self.path.name + "."
        for entry in self.path.parent.glob(self.path.name + ".*"):
            suffix = entry.name[len(prefix) :]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
        return highest

    def _maybe_rotate(self) -> None:
        """Rotate when over budget, carrying head into the new file.

        New file's first record uses prev_hash=old head, so per-file verify()
        holds and cross-file continuity is checkable by matching heads.
        Best-effort: rotation failure never blocks the request path.
        Must run under the exclusive lock (append holds it).
        """
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                backup = self._next_segment_path()
                self.path.rename(backup)
                uri = archive_to_s3(backup, self.s3_bucket, self.s3_prefix)
                if uri:
                    self._archived.add(backup.name)
                    log.info("audit rotated, archived %s", uri)
                self._prune_archived()
        except OSError:
            pass

    def append(self, tenant: str, event: str, payload: dict, request_id: str = "") -> AuditRecord:
        """Server-side cost breakdown lands in the metrics singleton.

        Two counters per append: lock-wait seconds and hold seconds (the
        critical section: tail read, rotation check, write, fsync). Mean =
        sum / `aegis_audit_append_total`. Sums only, no percentiles — the
        registry holds counters, and a mean answers "is the audit lock the
        bottleneck" without pretending to show a tail it cannot see.
        """
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        payload_enc, payload_alg = encrypt_payload(payload_bytes, self.encrypt_key)
        item = (tenant, event, payload_sha256, payload_enc, payload_alg, request_id)
        if self.batch_window_ms > 0:
            return self._append_batched(item)
        return self._append_solo(item)

    def _write_batch(self, items: list[tuple]) -> list[AuditRecord]:
        """Mint seq, hash, write and fsync every item. One fsync for the batch.

        Must run under the exclusive lock. Rotation is checked once up front:
        a batch may push the file one batch over budget, which the next batch
        rotates — bounded overshoot, never silent loss.
        """
        # adopt seq/head minted by sibling workers, then rotate, then write —
        # all atomically, so multi-worker uvicorn can't fork the chain.
        self._refresh_from_tail()
        self._maybe_rotate()
        records = []
        lines = []
        for tenant, event, payload_sha256, payload_enc, payload_alg, request_id in items:
            ts = time.time()
            self.seq += 1
            entry_hash = self._entry_hash(self.seq, ts, tenant, event, payload_sha256, self.head, request_id)
            records.append(
                AuditRecord(
                    seq=self.seq,
                    ts=ts,
                    tenant=tenant,
                    event=event,
                    payload_sha256=payload_sha256,
                    prev_hash=self.head,
                    entry_hash=entry_hash,
                    payload_enc=payload_enc,
                    payload_alg=payload_alg,
                    request_id=request_id,
                )
            )
            lines.append(json.dumps(records[-1].__dict__, separators=(",", ":")))
            self.head = entry_hash
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return records

    def _append_solo(self, item: tuple) -> AuditRecord:
        start_wait = time.perf_counter()
        with self._locked(exclusive=True):
            wait_s = time.perf_counter() - start_wait
            start_hold = time.perf_counter()
            records = self._write_batch([item])
            hold_s = time.perf_counter() - start_hold
        # Outside the lock: recording must never extend the critical section.
        _report_append(batched=False, count=1, wait_s=wait_s, hold_s=hold_s)
        return records[0]

    def _append_batched(self, item: tuple) -> AuditRecord:
        """Leader-follower group commit. No background thread to leak, stall or
        drain at shutdown: the first thread in a window becomes the flusher,
        sleeps one window to collect followers, then writes the batch with one
        fsync and wakes everyone. Ack still waits for the fsync, so a record is
        never reported before it is durable — the window costs latency, never
        safety. A follower whose leader dies falls back to a solo append."""
        slot: dict = {"done": threading.Event(), "record": None, "error": None, "item": item}
        with self._batch_lock:
            self._batch.append(slot)
            leader = len(self._batch) == 1
        if not leader:
            if slot["done"].wait(timeout=self.batch_window_ms / 1000 + 30):
                if slot["error"] is not None:
                    raise slot["error"]
                return slot["record"]
            with self._batch_lock:
                if slot["done"].is_set():
                    # The leader flushed while we timed out: use its result,
                    # never write the same record twice.
                    if slot["error"] is not None:
                        raise slot["error"]
                    return slot["record"]
                if slot in self._batch:
                    self._batch.remove(slot)
            return self._append_solo(item)
        time.sleep(self.batch_window_ms / 1000)
        with self._batch_lock:
            batch = self._batch
            self._batch = []
        start_wait = time.perf_counter()
        try:
            with self._locked(exclusive=True):
                wait_s = time.perf_counter() - start_wait
                start_hold = time.perf_counter()
                records = self._write_batch([s["item"] for s in batch])
                hold_s = time.perf_counter() - start_hold
        except Exception as exc:  # noqa: BLE001 — every waiter must wake, with the cause attached
            for s in batch:
                s["error"] = exc
                s["done"].set()
            raise
        _report_append(batched=True, count=len(batch), wait_s=wait_s, hold_s=hold_s)
        for s, record in zip(batch, records, strict=True):
            s["record"] = record
            s["done"].set()
        return slot["record"]

    def purge_old_payloads(self, max_age_days: float) -> int:
        """Null encrypted payload copies older than `max_age_days`.

        Data minimization for regulated deployments: the *hash* of every
        payload stays (so `verify()` is unaffected — `entry_hash` covers
        `payload_sha256`, never the encrypted copy), but the recoverable
        content goes. Files rewrite atomically under the exclusive lock; the
        purge itself appends a `payload_purge` record with the count, so the
        expiry is audited rather than silent. 0 or negative disables.
        """
        if max_age_days <= 0:
            return 0
        # No mtime shortcut: the live file is always freshly modified and
        # still holds old records, so file age says nothing about record age.
        # Full scan costs O(chain) per tick — the same class as the
        # reconciler's status(refresh=True) on the same tick.
        cutoff = time.time() - max_age_days * 86400
        purged = 0
        with self._locked(exclusive=True):
            for path in discover_segments(self.path):
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except OSError:
                    continue
                out = []
                changed = False
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)
                    except ValueError:
                        out.append(line)
                        continue
                    if raw.get("ts", 0) < cutoff and raw.get("payload_enc") is not None:
                        raw["payload_enc"] = None
                        raw["payload_alg"] = "none"
                        purged += 1
                        changed = True
                    out.append(json.dumps(raw, separators=(",", ":")))
                if changed:
                    tmp = path.with_suffix(path.suffix + ".purge-tmp")
                    try:
                        tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
                        os.replace(tmp, path)
                    except OSError:
                        try:
                            tmp.unlink()
                        except OSError:
                            pass
        if purged:
            self.append("admin", "payload_purge", {"purged": purged, "max_age_days": max_age_days})
        return purged

    def verify(self) -> tuple[bool, str]:
        try:
            with self._locked(exclusive=False):
                self._load()
            return True, f"chain intact, head={self.head[:12]}…, length={self.seq}"
        except AuditError as exc:
            return False, str(exc)

    def probe(self) -> tuple[bool, str]:
        """O(1) readiness check: signature-verify only the tail record.

        `verify()` re-reads every line, so its cost grows with chain length —
        a liveness probe must not do that (M13). The full chain was verified
        at boot (`_load` in `__init__`) and every append re-checks linkage
        under lock, so per-probe work is one tail read plus one HMAC.
        """
        try:
            with self._locked(exclusive=False):
                tail = self._read_tail()
                if tail is None:
                    return True, "chain empty, ready"
                ok, _slot = self._verify_entry(tail)
                if not ok:
                    return False, f"audit tail corrupt at seq={tail.seq}"
                return True, f"tail ok, head={tail.entry_hash[:12]}…, length={tail.seq}"
        except (OSError, AuditError) as exc:
            return False, f"audit probe failed: {exc}"

    # -- read side (evidence inspection) -------------------------------------

    def _tail_lines(self, want: int, block: int = 65536) -> tuple[list[str], bool]:
        """Return (up to `want` trailing non-empty lines oldest→newest, reached_start).

        Reads backwards in fixed-size blocks. A whole-file read is what makes
        `/readyz` expensive on a full log; the read API must not repeat that, so
        cost here is O(want) regardless of how large the log has grown.
        """
        try:
            size = self.path.stat().st_size
        except OSError:
            return [], True
        if size == 0:
            return [], True

        lines: list[str] = []
        buf = b""
        pos = size
        with self.path.open("rb") as fh:
            while pos > 0 and len(lines) < want:
                step = min(block, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                # The first part continues into earlier file content unless we
                # just reached offset 0; the last part is always a whole line.
                buf = parts.pop(0) if pos > 0 else b""
                for raw in reversed(parts):
                    text = raw.decode("utf-8", "replace").strip()
                    if text:
                        lines.append(text)
                        if len(lines) >= want:
                            break
        lines.reverse()
        return lines, pos == 0

    def tail_records(self, limit: int = 50, tenant: str = "", event: str = "", with_payload: bool = True) -> dict:
        """Newest-first-selected evidence, with every signature re-verified.

        Each returned record carries:
          sig_ok   — entry_hash recomputed under the chain key matches
          link_ok  — prev_hash matches the preceding record's entry_hash
                     (None for the oldest row when the window doesn't reach the
                     file start: its predecessor was never read, and claiming
                     otherwise would be a fabricated assurance)
          payload  — decrypted payload dict, or None when payload copies are off
          payload_ok — sha256(decrypted bytes) == the signed payload_sha256

        `payload_ok` is the property that makes the visible evidence trustworthy:
        it ties what you are reading back to the digest that is inside the HMAC.
        """
        limit = max(1, min(int(limit), MAX_READ_RECORDS))
        filtered = bool(tenant or event)
        # One extra line gives the oldest returned record its linkage anchor.
        window = MAX_READ_RECORDS if filtered else min(limit + 1, MAX_READ_RECORDS)

        with self._locked(exclusive=False):
            lines, reached_start = self._tail_lines(window)

        parsed: list[AuditRecord] = []
        malformed: list[dict] = []
        for line in lines:
            try:
                raw = json.loads(line)
                raw.setdefault("payload_enc", None)
                raw.setdefault("payload_alg", "none")
                raw.setdefault("request_id", "")
                parsed.append(AuditRecord(**{k: raw[k] for k in AuditRecord.__dataclass_fields__}))
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                # A corrupt line is evidence too — surface it rather than skip.
                malformed.append({"error": f"{type(exc).__name__}: {exc}", "line": line[:200]})

        rows: list[dict] = []
        prev: AuditRecord | None = None
        for rec in parsed:
            sig_ok, key_slot = self._verify_entry(rec)
            if prev is None:
                link_ok: bool | None = rec.prev_hash == "GENESIS" if reached_start else None
            else:
                link_ok = rec.prev_hash == prev.entry_hash

            payload: dict | None = None
            payload_ok: bool | None = None
            if with_payload and rec.payload_enc and rec.payload_alg != "none":
                try:
                    blob = decrypt_payload(rec.payload_enc, rec.payload_alg, self.encrypt_key)
                    payload_ok = hashlib.sha256(blob).hexdigest() == rec.payload_sha256
                    payload = json.loads(blob)
                except Exception as exc:  # noqa: BLE001 — bad cipher is reported, not raised
                    payload = {"error": f"undecryptable: {type(exc).__name__}"}
                    payload_ok = False

            rows.append(
                {
                    "seq": rec.seq,
                    "ts": rec.ts,
                    "tenant": rec.tenant,
                    "event": rec.event,
                    "request_id": rec.request_id,
                    "payload_sha256": rec.payload_sha256,
                    "entry_hash": rec.entry_hash,
                    "prev_hash": rec.prev_hash,
                    "sig_ok": sig_ok,
                    "signed_with": "current" if key_slot == 0 else f"previous:{key_slot - 1}",
                    "link_ok": link_ok,
                    "payload": payload,
                    "payload_ok": payload_ok,
                }
            )
            prev = rec

        if tenant:
            rows = [r for r in rows if r["tenant"] == tenant]
        if event:
            rows = [r for r in rows if r["event"] == event]
        selected = rows[-limit:]

        return {
            "records": selected,
            "count": len(selected),
            "scanned": len(lines),
            "malformed": malformed,
            "window_reached_start": reached_start,
            "truncated": (not reached_start) and len(rows) > len(selected),
            "all_signatures_valid": all(r["sig_ok"] for r in selected),
            "all_links_valid": all(r["link_ok"] is not False for r in selected),
            "payload_available": bool(self.encrypt_key),
            # The algorithm actually in use, not the one the key implies. With
            # `cryptography` absent the payload copy is base64, and saying
            # "fernet" here would have the console promise encryption the file
            # does not have.
            "payload_alg": payload_cipher_alg(self.encrypt_key),
            "payload_encrypted": payload_cipher_alg(self.encrypt_key) == "fernet",
            "chain": {"head": self.head, "length": self.seq},
        }


def load_verified_records(path: str | Path, hmac_key: str, hmac_previous_keys: Sequence[str] = ()) -> list[AuditRecord]:
    """Parse one segment file, verifying every signature and link.

    Same checks as AuditChain._load, but standalone so reconcile can name
    the offending file. Raises AuditError (tamper) or OSError (unreadable).
    """
    p = Path(path)
    verifier = AuditChain.__new__(AuditChain)
    # Mirror AuditChain.__init__'s keyring. This deliberately bypasses
    # __init__ (there is no file to adopt a head from), so the keyring has to
    # be built here too -- and if a rotation makes segments unreadable, this is
    # where it would show up.
    verifier._keys = [hmac_key.encode()] + [
        k.encode() for k in hmac_previous_keys if k and k != hmac_key and k.encode() != hmac_key.encode()
    ]
    verifier._key = verifier._keys[0]
    records: list[AuditRecord] = []
    last: AuditRecord | None = None
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            raw.setdefault("payload_enc", None)
            raw.setdefault("payload_alg", "none")
            raw.setdefault("request_id", "")
            rec = AuditRecord(**{k: raw[k] for k in AuditRecord.__dataclass_fields__})
            ok, _slot = verifier._verify_entry(rec)
            if not ok:
                raise AuditError(f"{p}: chain corrupt at seq={rec.seq}")
            if last is not None and rec.prev_hash != last.entry_hash:
                raise AuditError(f"{p}: broken linkage at seq={rec.seq}")
            records.append(rec)
            last = rec
    return records


def _segment_sort_key(name: str) -> int:
    """Sort `audit.jsonl.10` after `audit.jsonl.9` rather than before it."""
    suffix = name.rsplit(".", 1)[-1]
    return int(suffix) if suffix.isdigit() else 1 << 30


def discover_segments(path: str | Path) -> list[Path]:
    """Every on-disk segment of one ledger, oldest first, live file last.

    Callers used to hand-assemble this list, which meant a rotated ledger was
    reconciled from whatever subset someone remembered to pass -- the failure
    mode being a clean-looking chain that quietly omits most of the history.
    """
    base = Path(path)
    segments: list[tuple[int, Path]] = []
    for entry in base.parent.glob(base.name + "*"):
        suffix = entry.name[len(base.name) :]
        if not (suffix == "" or suffix.lstrip(".").isdigit()):
            continue
        if entry.name.endswith(".lock") or not entry.is_file():
            continue
        segments.append((int(suffix.lstrip(".")) if suffix else 1 << 30, entry))
    return [p for _, p in sorted(segments)]


def fetch_s3_segments(
    bucket: str,
    cache_dir: str | Path,
    prefix: str = "aegis-audit/",
    hmac_key: str | None = None,
) -> list[Path]:
    """Download archived audit segments so they can be reconciled.

    Archiving was a one-way trip: rotation uploaded a sealed segment and nothing
    could bring it back, so a pruned or restarted host had no way to see the
    history it had already written. This is the return path.

    `hmac_key`, when given, keeps only objects that actually verify. An
    attacker with write access to the bucket could otherwise drop well-formed
    junk into the ledger and have it counted -- archive objects are untrusted
    input until proven otherwise.

    Returns the local paths, and never raises: a ledger that cannot reach object
    storage must still reconcile what it has on disk.
    """
    if not bucket:
        return []
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError:
        log.warning("audit s3 fetch skipped: install the 'archive' extra for boto3")
        return []

    dest = Path(cache_dir)
    dest.mkdir(parents=True, exist_ok=True)
    key_prefix = prefix.rstrip("/")
    found: list[Path] = []
    try:
        client = boto3.client("s3")
        token = None
        while True:
            extra_args: dict[str, str] = {"ContinuationToken": token} if token else {}
            page = client.list_objects_v2(Bucket=bucket, Prefix=f"{key_prefix}/", **extra_args)
            for item in page.get("Contents", []) or []:
                name = str(item.get("Key", "")).rsplit("/", 1)[-1]
                # A segment is `<ledger>.jsonl` or `<ledger>.jsonl.<n>`. Anything
                # else under a shared prefix is not ledger -- `audit.jsonl.gz`
                # in particular, which a substring check would happily accept.
                tail = name[len("audit.jsonl") :] if name.startswith("audit.jsonl") else None
                if tail is None:
                    continue
                if tail != "" and not tail.lstrip(".").isdigit():
                    continue
                target = dest / name
                if not target.exists():
                    client.download_file(bucket, str(item["Key"]), str(target))
                if hmac_key is not None:
                    try:
                        load_verified_records(target, hmac_key)
                    except (AuditError, OSError, ValueError, KeyError) as exc:
                        log.warning("audit s3 object %s rejected: %s", name, exc)
                        target.unlink(missing_ok=True)
                        continue
                found.append(target)
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
            if not token:
                break
    except Exception as exc:  # noqa: BLE001 — archive access never blocks reconciliation
        log.warning("audit s3 fetch failed: %s", exc)
    return sorted(found, key=lambda p: _segment_sort_key(p.name))


class FleetLedger:
    """Reconciled view across every segment of one ledger, cached.

    `reconcile_segments` existed with no caller, so a rotated ledger was never
    assembled: the admin view called `audit.verify()`, which reads the live
    file alone, so every rotated segment -- most of the history -- was simply
    absent from what an operator was shown. This is the piece that makes the
    assembled view reachable, and it caches because assembly hashes every
    record in every segment and an admin page should not pay that per request.
    """

    def __init__(
        self,
        path: str | Path,
        hmac_key: str,
        hmac_previous_keys: Sequence[str] = (),
        extra_paths: Sequence[str | Path] = (),
        ttl_seconds: float = 30.0,
        s3_bucket: str = "",
        s3_prefix: str = "aegis-audit/",
        archive_cache: str | Path | None = None,
    ) -> None:
        self.path = Path(path)
        self.hmac_key = hmac_key
        self.hmac_previous_keys = tuple(hmac_previous_keys)
        self.extra_paths = tuple(Path(p) for p in extra_paths)
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix
        self.archive_cache = Path(archive_cache) if archive_cache else Path(path).parent / "archive-cache"
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._cached: dict | None = None
        self._computed_at = 0.0

    def invalidate(self) -> None:
        with self._lock:
            self._cached = None

    def segments(self) -> list[Path]:
        """Live ledger segments first, then any externally supplied ones.

        `extra_paths` covers segments restored from object storage or fetched
        from another replica -- the cases a single host cannot see on its own.
        """
        return [*discover_segments(self.path), *self.extra_paths]

    def sync_from_archive(self) -> list[Path]:
        """Pull archived segments in, then invalidate so they are counted.

        Called from the background reconciler rather than from `status`, because
        status must stay cheap and must not do network I/O on an admin read.
        """
        if not self.s3_bucket:
            return []
        fetched = fetch_s3_segments(
            self.s3_bucket,
            self.archive_cache,
            self.s3_prefix,
            self.hmac_key,
        )
        if fetched:
            known = {p.name for p in self.extra_paths}
            self.extra_paths = (*self.extra_paths, *[p for p in fetched if p.name not in known])
            self.invalidate()
        return fetched

    def status(self, refresh: bool = False) -> dict:
        """Assemble the ledger, or return the cached assembly while it is fresh.

        `complete` is the field to gate on. A false one means records are
        provably missing -- either an unreadable segment, a sequence break
        inside a chain, or a chain whose predecessor is gone.
        """
        now = time.monotonic()
        with self._lock:
            fresh = self._cached is not None and not refresh and (now - self._computed_at) < self.ttl_seconds
            if fresh:
                cached = dict(self._cached or {})
                cached["age_s"] = round(now - self._computed_at, 3)
                cached["cached"] = True
                return cached

            paths: list[str | Path] = list(self.segments())
            assembled = reconcile_segments(paths, self.hmac_key, self.hmac_previous_keys)
            per_segment = []
            for path in paths:
                key = str(path)
                if key in assembled["errors"]:
                    per_segment.append({"segment": Path(path).name, "records": 0, "readable": False})
                    continue
                records = len(load_verified_records(path, self.hmac_key, self.hmac_previous_keys))
                per_segment.append({"segment": Path(path).name, "records": records, "readable": True})

            self._computed_at = now
            self._cached = {
                "segments": len(paths),
                "chains": len(assembled["chains"]),
                "records": assembled["records"],
                "complete": assembled["complete"],
                "errors": {Path(k).name: v for k, v in assembled["errors"].items()},
                "seq_gaps": assembled["seq_gaps"],
                "starts_mid_sequence": [
                    {**m, "segment": Path(m["segment"]).name} for m in assembled["starts_mid_sequence"]
                ],
                "per_segment": per_segment,
                "longest_chain": max((len(c) for c in assembled["chains"]), default=0),
            }
            result = dict(self._cached)
            result["age_s"] = 0.0
            result["cached"] = False
            return result


def reconcile_segments(paths: list[str | Path], hmac_key: str, hmac_previous_keys: Sequence[str] = ()) -> dict:
    """Order per-pod audit segments by head linkage (M12).

    Verifies every segment, then chains them: segment B follows A when B's
    first prev_hash equals A's last entry_hash (rotation carry-over).
    Segments sharing no link are different pods — reported as separate
    chains, which is expected, not corruption. Tampered/unreadable files
    land in `errors` and never poison a chain.

    Continuity is reported, not assumed. A lost segment breaks the hash link,
    which on its own is indistinguishable from a second pod writing its own
    chain — so both halves of the trail look equally healthy while records are
    missing. `seq_gaps` and `starts_mid_sequence` close that gap by checking
    the sequence counter across each assembled chain: sequence numbers only
    advance, so a break is proof that something was dropped. `complete` is the
    single field a caller should gate on.
    """
    verified: dict[str, list[AuditRecord]] = {}
    errors: dict[str, str] = {}
    for raw_path in paths:
        name = str(raw_path)
        if name in verified or name in errors:
            continue
        try:
            verified[name] = load_verified_records(name, hmac_key, hmac_previous_keys)
        except (AuditError, OSError, ValueError, KeyError) as exc:
            errors[name] = str(exc)
    firsts = {n: recs[0].prev_hash for n, recs in verified.items() if recs}
    next_of: dict[str, str] = {}
    for name, recs in verified.items():
        if not recs:
            continue
        for other, first_prev in firsts.items():
            if other != name and first_prev == recs[-1].entry_hash:
                next_of[name] = other
                break
    starts = sorted(n for n in verified if n not in next_of.values())
    chains: list[list[str]] = []
    for start in starts:
        chain, seen = [start], {start}
        # The next name must be read before the append. Written as
        # `chain.append(next_of[chain[-1]])` followed by
        # `seen.add(next_of[chain[-1]])`, the second line reads chain[-1]
        # *after* the append and marks the segment two steps ahead, so the walk
        # stopped one step early and every chain was truncated to two segments.
        # Nothing caught it because no caller existed.
        while chain[-1] in next_of:
            nxt = next_of[chain[-1]]
            if nxt in seen:
                break
            chain.append(nxt)
            seen.add(nxt)
        chains.append(chain)

    seq_gaps: list[dict] = []
    starts_mid_sequence: list[dict] = []
    all_seqs = [r.seq for recs in verified.values() for r in recs]
    baseline = min(all_seqs) if all_seqs else 0
    for chain in chains:
        # Only the first segment of a chain carries information: mid-chain
        # segments are *expected* to begin above the baseline, since they
        # follow their predecessor. A chain that begins above the observed
        # minimum is a chain whose predecessor is gone.
        first = verified.get(chain[0]) if chain else None
        if first:
            # The baseline is the observed minimum, not 0, because sequence
            # numbers start at 1 and a pod's first segment legitimately does.
            if first[0].seq > baseline:
                starts_mid_sequence.append(
                    {
                        "segment": chain[0],
                        "first_seq": first[0].seq,
                        "baseline_seq": baseline,
                        "missing_before": first[0].seq - baseline,
                    }
                )
        flat = [r for name in chain for r in verified[name]]
        for prev, cur in zip(flat, flat[1:], strict=False):
            if cur.seq != prev.seq + 1:
                seq_gaps.append(
                    {
                        "after_seq": prev.seq,
                        "expected_seq": prev.seq + 1,
                        "found_seq": cur.seq,
                        "missing": max(0, cur.seq - prev.seq - 1),
                    }
                )
    return {
        "chains": chains,
        "records": sum(len(verified[n]) for chain in chains for n in chain),
        "errors": errors,
        "seq_gaps": seq_gaps,
        "starts_mid_sequence": starts_mid_sequence,
        "complete": not errors and not seq_gaps and not starts_mid_sequence,
    }
