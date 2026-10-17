"""M6: embedding I/O must never block the event loop.

A provider whose sync `embed` sleeps (API latency) must not stall concurrent
requests: `aretrieve`/`aprepare` prefer `aembed`, else run sync work in a
worker thread. A heartbeat task measures loop stall while retrieval runs.
"""

import asyncio
import time

from aegis.rag.ingest import chunk_document
from aegis.rag.retriever import HybridRetriever
from aegis.rag.service import RagService


class SlowSyncProvider:
    """Sync path sleeps like a real API; async path is instant."""

    name = "slow-sync"
    SLEEP = 0.3

    def __init__(self) -> None:
        self.sync_calls = 0
        self.async_calls = 0

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.sync_calls += 1
        time.sleep(self.SLEEP)
        return [[1.0] for _ in texts]

    async def aembed(self, texts: list[str]) -> list[list[float]]:
        self.async_calls += 1
        return [[1.0] for _ in texts]


class SyncOnlyProvider(SlowSyncProvider):
    """Legacy provider shape: sync `embed` only, no `aembed` at all."""

    name = "sync-only"
    aembed = None  # type: ignore[assignment] — genuinely absent on legacy providers


async def _heartbeat(counter: list[float], stop: asyncio.Event) -> None:
    while not stop.is_set():
        counter.append(asyncio.get_running_loop().time())
        await asyncio.sleep(0.01)


def _max_gap(stamps: list[float]) -> float:
    return max((b - a for a, b in zip(stamps, stamps[1:], strict=False)), default=0.0)


def _retriever(provider: object) -> HybridRetriever:
    r = HybridRetriever(embed_provider=provider)
    r.index(chunk_document("the office wifi password is printed at reception", "wifi-access.md"))
    return r


async def test_aretrieve_prefers_aembed_and_does_not_stall_loop() -> None:
    provider = SlowSyncProvider()
    retr = _retriever(provider)
    assert provider.sync_calls == 1  # sync index path unchanged

    ticks: list[float] = []
    stop = asyncio.Event()
    beat = asyncio.create_task(_heartbeat(ticks, stop))
    try:
        results = await retr.aretrieve("wifi password reception")
    finally:
        stop.set()
        await beat

    assert provider.sync_calls == 1, "aretrieve must not touch blocking embed"
    assert provider.async_calls >= 1
    assert results and results[0].chunk.source == "wifi-access.md"
    assert _max_gap(ticks) < SlowSyncProvider.SLEEP, f"loop stalled: {ticks}"


async def test_aretrieve_without_aembed_runs_sync_work_off_loop() -> None:
    provider = SyncOnlyProvider()
    assert getattr(provider, "aembed", None) is None
    r = HybridRetriever(embed_provider=provider)
    # Index synchronously here (setup, not the request path under test).
    r.index(chunk_document("the office wifi password is printed at reception", "wifi-access.md"))

    ticks: list[float] = []
    stop = asyncio.Event()
    beat = asyncio.create_task(_heartbeat(ticks, stop))
    try:
        results = await r.aretrieve("wifi password reception")
    finally:
        stop.set()
        await beat

    assert results and results[0].chunk.source == "wifi-access.md"
    assert _max_gap(ticks) < SyncOnlyProvider.SLEEP, f"loop stalled: {ticks}"


async def test_aprepare_matches_prepare() -> None:
    svc = RagService()
    svc.ingest("the office wifi password is printed at reception", "wifi-access.md")
    sync_ctx = svc.prepare("wifi password?", "default")
    async_ctx = await svc.aprepare("wifi password?", "default")
    assert async_ctx.question == sync_ctx.question
    assert async_ctx.system_prompt == sync_ctx.system_prompt
    assert [c["chunk_id"] for c in async_ctx.citations] == [c["chunk_id"] for c in sync_ctx.citations]
