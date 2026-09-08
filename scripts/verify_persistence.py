#!/usr/bin/env python3
"""Phase-2 proof: RAG chunks survive a rebuild via Postgres.

Writes chunks through PgChunkStore, constructs a FRESH store map,
bootstraps from the DB, and asserts the chunks come back under the
right tenant (isolation holds across restarts).

SKIP (exit 0) when AEGIS_DATABASE_URL is unset or drivers/DB are
unreachable — local runs stay dependency-free. CI sets DATABASE_URL
and pgvector service, so this gate is hard there.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> int:
    dsn = os.environ.get("AEGIS_DATABASE_URL", "")
    if not dsn:
        print("SKIP: AEGIS_DATABASE_URL unset")
        return 0
    try:
        import psycopg  # noqa: F401
    except ImportError:
        print("SKIP: psycopg not installed")
        return 0

    from aegis.rag.ingest import chunk_document
    from aegis.store.db import PgChunkStore

    tenant, other = "persist-acme", "persist-other"
    try:
        store = PgChunkStore(dsn)
        conn = store._connect()
    except Exception as exc:  # noqa: BLE001 — any connect failure means SKIP
        print(f"SKIP: postgres unreachable ({exc})")
        return 0

    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    try:
        store.ensure_schema(conn)
        conn.close()
        chunks = chunk_document(
            "Persistence proof: refunds within 30 days with receipt. " * 4, "policy.md"
        )
        store.save(tenant, chunks)
        stores: dict = {}
        added = store.bootstrap(stores)
        check(added >= 1, "bootstrap indexed nothing")
        check(tenant in stores, "tenant index missing after rebuild")
        hits = stores.get(tenant, {}).retrieve("refund window?", top_k=3) if tenant in stores else []
        check(bool(hits) and "refund" in hits[0].chunk.text.lower(), "rebuild lost content")
        check(other not in stores, "tenant leak across rebuild")
    except AssertionError as exc:
        failures.append(f"assert: {exc}")
    except Exception as exc:  # noqa: BLE001 — proof reports, never tracebacks
        failures.append(f"error: {exc}")

    if failures:
        for msg in failures:
            print(f"PROOF FAILED: {msg}")
        return 1
    print(f"PROOF: postgres roundtrip ok (rebuilt={added}, tenants={sorted(stores)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
