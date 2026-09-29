"""Shutdown draining, tested against the behaviour a rolling deploy depends on.

Without a drain, SIGTERM tears the gateway down while requests are still
executing. The specific failure that matters here is not a 500: it is a request
interrupted between "the provider answered" and "the audit record was written".
The user is charged for an answer that leaves no evidence it happened, which is
the one outcome this product exists to make impossible. That is invisible in a
status-code assertion, so the tests below check the ordering and the accounting
rather than just the response code.
"""

from __future__ import annotations

import asyncio
import hashlib

import pytest
from starlette.testclient import TestClient

from aegis.api.middleware import DRAIN_EXEMPT_PATHS, DrainMiddleware, current_drain
from aegis.api.routes import app as APP


def _counter_only(timeout: float) -> DrainMiddleware:
    """A middleware for exercising the counter without a deployment.

    Built with ``app=None`` on purpose: a middleware constructed without an app
    does not register itself, so these scenarios cannot clobber the drain the
    serving app is using. An earlier version of this file passed a dummy app
    object and silently took over the global, which is the kind of thing that
    fails in a full-suite run and passes in isolation.
    """
    return DrainMiddleware(app=None, timeout=timeout)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import asyncio as _a

    monkeypatch.chdir(tmp_path)
    from aegis.api.routes import STATE
    from aegis.config import Settings
    from aegis.gateway import build_gateway
    from aegis.metrics import metrics
    from aegis.security.auth import Authenticator

    settings = Settings(
        env="test",
        tenants=(
            f"ops:{hashlib.sha256(b'k').hexdigest()}:chat+rag+admin,"
            f"acme:{hashlib.sha256(b'j').hexdigest()}:chat+rag"
        ),
        providers="echo",
        rate_limit_per_min=1000,
        daily_token_budget=10_000_000,
        audit_hmac_key="test-audit-key-32-chars-minimum!!",
        vault_hmac_key="test-vault-key-32-chars-minimum!!!",
        admin_username="operator",
        admin_password="unit-test-admin-password",  # noqa: S106 — test fixture credential
        admin_session_key="test-admin-session-key-32-chars-lol",
    )
    STATE["settings"] = settings
    STATE["gateway"] = _a.run(build_gateway(settings))
    STATE["authenticator"] = Authenticator(settings)
    metrics.clear()
    with TestClient(APP) as c:
        yield c
    STATE["gateway"].ops.clear()
    metrics.clear()


def test_a_freshly_started_app_is_not_draining(client):
    assert current_drain() is not None
    assert current_drain().draining is False
    assert client.get("/healthz").status_code == 200


def test_requests_are_refused_while_draining(client):
    """Refusing early is what lets the drain finish.

    A proxy that keeps sending work to a pod which never refuses will hold
    shutdown open until the orchestrator's grace period expires.
    """
    drain = current_drain()
    drain.begin_drain()
    try:
        r = client.post(
            "/v1/chat",
            headers={"Authorization": "Bearer k"},
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        assert r.status_code == 503
        assert r.headers["Retry-After"] == "5"
    finally:
        drain.end_drain()


def test_probes_keep_answering_while_draining(client):
    """Otherwise the liveness probe kills a pod that is shutting down cleanly,
    instead of the load balancer moving traffic off it politely."""
    drain = current_drain()
    drain.begin_drain()
    try:
        for path in sorted(DRAIN_EXEMPT_PATHS):
            r = client.get(path)
            assert r.status_code != 503, f"{path} stopped answering while draining"
    finally:
        drain.end_drain()


def test_traffic_resumes_after_a_drain_is_cleared(client):
    drain = current_drain()
    drain.begin_drain()
    drain.end_drain()
    r = client.post(
        "/v1/chat",
        headers={"Authorization": "Bearer k"},
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert r.status_code == 200, r.text


def test_the_drain_waits_for_work_in_flight():
    """The accounting itself, without needing a slow HTTP server.

    `wait_for_idle` returning early is the bug that would truncate an audit
    write, so this drives the counter directly and checks both outcomes: it
    returns True when work finishes, and False -- rather than hanging -- when it
    does not.
    """
    mw = _counter_only(0.2)

    async def scenario() -> bool:
        mw._in_flight = 1
        mw._idle_event().clear()
        return await mw.wait_for_idle()

    assert asyncio.run(scenario()) is False, "a hung drain must not block forever"

    async def finishing() -> bool:
        idle = mw._idle_event()
        mw._in_flight = 1
        idle.clear()

        async def complete() -> None:
            await asyncio.sleep(0.02)
            mw._in_flight = 0
            idle.set()

        task = asyncio.create_task(complete())
        result = await mw.wait_for_idle()
        await task
        return result

    assert asyncio.run(finishing()) is True, "the drain ignored work finishing"


def test_the_drain_gives_up_rather_than_hanging_forever():
    """A provider that hangs must not be able to hold a deploy open.

    `wait_for_idle` returning False is the signal the shutdown path logs and
    reports, so the operator learns the drain was incomplete instead of the
    process blocking until SIGKILL.
    """
    mw = _counter_only(0.05)

    async def scenario() -> bool:
        mw._in_flight = 1
        mw._idle_event().clear()
        return await mw.wait_for_idle()

    assert asyncio.run(scenario()) is False
    assert mw.in_flight == 1, "the hung request should still be counted"


def test_shutdown_does_not_leave_the_app_refusing_traffic(client):
    """The regression that bit during development.

    Starlette builds the middleware stack once per app and reuses it, so a drain
    set during one shutdown would still be set at the next startup. Under a test
    client that showed up as every later request getting a 503; behind a process
    supervisor that reuses an app object it would be the same bug in production.
    """
    from aegis.api.routes import STATE

    # A fresh client on the same app must come up serving, not draining.
    with TestClient(APP) as second:
        r = second.post(
            "/v1/chat",
            headers={"Authorization": "Bearer k"},
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        assert r.status_code == 200, "a new lifecycle inherited the previous drain"
    assert STATE["gateway"] is not None
