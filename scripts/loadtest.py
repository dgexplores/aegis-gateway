"""Load harness for the gateway.

Answers the question the 366-test suite cannot: *what does this do under
concurrency, and where does the time go?*

Three things it deliberately does:

* **It boots its own gateway** on a scratch port with the `echo` provider, so it
  is hermetic, free, and reproducible. Point `--base` at a running instance to
  test that instead.
* **It reports percentiles, not an average.** A mean hides the tail, and the
  tail is what a rate limiter, a breaker and a client timeout care about.
* **It sweeps the tenant count.** `Authenticator.authenticate` compares the
  presented hash against *every* stored hash, so its cost is O(tenants) on every
  request. That is a deliberate trade for a timing-safe scan, and it is fine at
  ten tenants and a problem at five hundred. The sweep is how you find out
  which side of that you are on instead of guessing.

What it does NOT measure, and this matters more than the numbers: real provider
latency. Everything here is the gateway's own overhead, which is the part this
codebase owns.

    python scripts/loadtest.py                     # boot and measure
    python scripts/loadtest.py --concurrency 50 --requests 5000
    python scripts/loadtest.py --base http://host:8080 --key sk-...   # a real one
    python scripts/loadtest.py --sweep-tenants 1 10 50 100
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_TENANT_KEY = "sk-loadtest-tenant-0000000000"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    # Nearest-rank: with a few hundred samples an interpolated percentile reads
    # as more precise than it is.
    rank = max(1, min(len(ordered), int(round(pct / 100.0 * len(ordered)))))
    return ordered[rank - 1]


def summarise(latencies: list[float], statuses: dict[str, int], wall: float) -> dict:
    return {
        "requests": len(latencies) + sum(v for k, v in statuses.items() if k == "error"),
        "completed": len(latencies),
        "errors": statuses.get("error", 0),
        "statuses": statuses,
        "wall_seconds": round(wall, 3),
        "throughput_rps": round(len(latencies) / wall, 1) if wall else 0.0,
        "latency_ms": {
            "min": round(min(latencies), 2) if latencies else 0.0,
            "p50": round(percentile(latencies, 50), 2),
            "p95": round(percentile(latencies, 95), 2),
            "p99": round(percentile(latencies, 99), 2),
            "max": round(max(latencies), 2) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies), 2) if latencies else 0.0,
        },
    }


async def hammer(base: str, key: str, total: int, concurrency: int,
                 payload: dict, mix_bad_auth: float = 0.0) -> dict:
    import httpx

    latencies: list[float] = []
    statuses: dict[str, int] = {}
    sem = asyncio.Semaphore(concurrency)
    remaining = total
    lock = asyncio.Lock()

    async with httpx.AsyncClient(base_url=base, timeout=30.0) as client:
        async def one(index: int) -> None:
            nonlocal remaining
            async with sem:
                # A slice of requests sent with a bad key, so the measurement
                # includes the rejection path and not only the happy one.
                bad = mix_bad_auth > 0 and (index % int(1 / mix_bad_auth) == 0)
                headers = {"Authorization": f"Bearer {'sk-wrong-key' if bad else key}",
                           "Content-Type": "application/json"}
                start = time.perf_counter()
                try:
                    r = await client.post("/v1/chat", headers=headers, json=payload)
                    bucket = str(r.status_code)
                except Exception:  # noqa: BLE001 — a transport failure is a datapoint
                    bucket = "error"
                    latencies.append((time.perf_counter() - start) * 1000)
                else:
                    latencies.append((time.perf_counter() - start) * 1000)
                statuses[bucket] = statuses.get(bucket, 0) + 1
                async with lock:
                    remaining -= 1

        started = time.perf_counter()
        await asyncio.gather(*(one(i) for i in range(total)))
        wall = time.perf_counter() - started
    return summarise(latencies, statuses, wall)


def report(label: str, result: dict) -> None:
    lat = result["latency_ms"]
    print(f"\n{label}")
    print(f"  requests   {result['requests']}  errors {result['errors']}  "
          f"statuses {result['statuses']}")
    print(f"  throughput {result['throughput_rps']} rps over {result['wall_seconds']}s")
    print(f"  latency ms p50 {lat['p50']}  p95 {lat['p95']}  p99 {lat['p99']}  "
          f"max {lat['max']}")


def boot_gateway(port: int, tenants: int) -> subprocess.Popen:
    """Start a gateway on `port` with `tenants` tenants sharing nothing."""
    workdir = Path(tempfile.mkdtemp(prefix="aegis-load-"))
    key = DEFAULT_TENANT_KEY
    import hashlib

    entries = [f"t0:{hashlib.sha256(key.encode()).hexdigest()}:chat+rag+admin"]
    for i in range(1, tenants):
        # Distinct keys, because two tenants sharing one is now a boot failure —
        # which is the right behaviour and inconvenient for a load test.
        entries.append(f"t{i}:{hashlib.sha256(f'{key}-{i}'.encode()).hexdigest()}:chat+rag")

    env = {
        **os.environ,
        "AEGIS_ENV": "development",
        "AEGIS_TENANTS": ",".join(entries),
        "AEGIS_PROVIDERS": "echo",
        "AEGIS_AUDIT_HMAC_KEY": "loadtest-audit-hmac-key-32-chars-min!!",
        "AEGIS_VAULT_HMAC_KEY": "loadtest-vault-hmac-key-32-chars-min!!!",
        "AEGIS_AUDIT_PATH": str(workdir / "audit.jsonl"),
        "AEGIS_RATE_LIMIT_PER_MIN": "1000000",
        "AEGIS_DAILY_TOKEN_BUDGET": "1000000000",
    }
    # Every argument here is a literal or an int we generated: no user input
    # reaches this call, which is what S603 is actually worried about.
    proc = subprocess.Popen(  # noqa: S603 — fixed argv, nothing interpolated from input
        [sys.executable, "-m", "uvicorn", "aegis.api.routes:app",
         "--host", "127.0.0.1", "--port", str(port), "--app-dir", str(ROOT / "src"),
         "--log-level", "warning"],
        env=env, cwd=str(workdir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc


def wait_until_up(port: int, timeout: float = 25.0) -> bool:
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return True
        except urllib.error.HTTPError:
            return True  # it answered, which is all we need
        except Exception:  # noqa: BLE001 — any failure here means "not up yet"
            time.sleep(0.25)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="an already-running gateway; omit to boot one")
    ap.add_argument("--key", default=DEFAULT_TENANT_KEY)
    ap.add_argument("--requests", type=int, default=2000)
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--mix-bad-auth", type=float, default=0.05,
                    help="fraction of requests sent with a wrong key (default 0.05)")
    ap.add_argument("--sweep-tenants", type=int, nargs="*", default=None,
                    help="tenant counts to compare, e.g. --sweep-tenants 1 10 50 100")
    ap.add_argument("--json", action="store_true", help="emit the raw numbers as JSON")
    args = ap.parse_args()

    payload = {"messages": [{"role": "user", "content": "What is our refund policy?"}]}
    results: dict[str, dict] = {}
    proc = None
    port = 0

    try:
        if args.base:
            base = args.base.rstrip("/")
        else:
            port = free_port()
            proc = boot_gateway(port, tenants=max(args.sweep_tenants or [1]))
            if not wait_until_up(port):
                print("loadtest: the gateway did not come up", file=sys.stderr)
                return 2
            base = f"http://127.0.0.1:{port}"

        result = asyncio.run(hammer(base, args.key, args.requests,
                                    args.concurrency, payload, args.mix_bad_auth))
        results["baseline"] = result
        report(f"baseline — {args.requests} requests, concurrency {args.concurrency}, "
               f"{len(args.sweep_tenants or [1]) or 1} tenant(s)", result)

        if args.sweep_tenants:
            print("\ntenant sweep — same load, growing tenant table")
            print("  (authenticate() compares the presented hash against every stored")
            print("   hash, so this is the O(tenants) term showing up in p50)")
            for n in sorted(set(args.sweep_tenants)):
                if n > 1 and not args.base:
                    port2 = free_port()
                    p2 = boot_gateway(port2, tenants=n)
                    if not wait_until_up(port2):
                        continue
                    try:
                        r = asyncio.run(hammer(f"http://127.0.0.1:{port2}", args.key,
                                               max(300, args.requests // 4),
                                               args.concurrency, payload, 0.0))
                    finally:
                        p2.terminate()
                else:
                    r = asyncio.run(hammer(base, args.key, max(300, args.requests // 4),
                                           args.concurrency, payload, 0.0))
                results[f"tenants_{n}"] = r
                print(f"  tenants {n:>4}  p50 {r['latency_ms']['p50']:>7} ms  "
                      f"p95 {r['latency_ms']['p95']:>7} ms  "
                      f"rps {r['throughput_rps']:>7}  errors {r['errors']}")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    if args.json:
        print(json.dumps(results, indent=2))
    return 0 if all(r["errors"] == 0 for r in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
