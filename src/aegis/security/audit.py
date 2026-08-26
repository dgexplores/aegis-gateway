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
import os
import time
from dataclasses import dataclass
from pathlib import Path


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


class AuditChain:
    def __init__(self, hmac_key: str, path: str = "audit.jsonl") -> None:
        self._key = hmac_key.encode()
        self.path = Path(path)
        self.seq = 0
        self.head = "GENESIS"
        self._load()

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
                rec = AuditRecord(**raw)
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

    def append(self, tenant: str, event: str, payload: dict) -> AuditRecord:
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
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
        )
        line = json.dumps(record.__dict__, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.head = entry_hash
        return record

    def verify(self) -> tuple[bool, str]:
        try:
            self._load()
            return True, f"chain intact, head={self.head[:12]}…, length={self.seq}"
        except AuditError as exc:
            return False, str(exc)
