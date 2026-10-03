"""Request middleware: request IDs, latency headers, and shutdown draining."""

import asyncio
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from aegis.context import request_id_ctx


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request_id_ctx.set(request_id)
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - start) * 1000
        response.headers["x-request-id"] = request_id
        response.headers["x-latency-ms"] = f"{latency_ms:.1f}"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defense-in-depth response headers (Standard §7).

    HSTS is honored by browsers only over HTTPS; harmless on local HTTP.

    The CSP is strict: no `unsafe-inline` for script or style, and no remote
    origins at all. That is only possible because the dashboard ships its own
    CSS and JS from /static instead of pulling Tailwind, a font host and a
    diagramming library off the public internet — which is also what makes the
    console usable on an air-gapped network, the environment this product is
    actually sold into.
    """

    HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'none'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        ),
    }

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in self.HEADERS.items():
            response.headers.setdefault(name, value)
        return response


class DrainMiddleware(BaseHTTPMiddleware):
    """Stop accepting work, then let in-flight work finish.

    A rolling deploy sends SIGTERM and starts a replacement immediately. Without
    this, `aclose()` runs while requests are still executing, so a request can
    be cut off between "the provider answered" and "the audit record was
    written" -- a user charged for an answer that leaves no evidence it happened,
    which is the one outcome this product exists to make impossible.

    Two states, deliberately distinct:

    * **draining** — new requests are refused with `503` and a `Retry-After`,
      so a load balancer moves on to the next replica instead of holding a
      connection open to a process that is going away. Refusing early is what
      makes the drain finish; a proxy that keeps sending work to a pod that
      never refuses will hold shutdown open indefinitely.
    * **drained** — the in-flight count reached zero, or the timeout expired.

    The timeout is not optional. A provider that hangs must not be able to hold
    a deploy open forever, so the drain gives up and says so rather than
    blocking SIGKILL for the orchestrator's grace period.
    """

    def __init__(self, app, timeout: float = 20.0) -> None:
        super().__init__(app)
        # Registered so the lifespan shutdown hook can reach the instance.
        # `app.user_middleware` holds the class and its constructor args, not
        # the object the server built, and there is no supported way to walk the
        # stack back out. One process serves one app, so a module-level
        # reference is the honest amount of machinery here.
        global _CURRENT
        # Only a real deployment registers. An instance built with `app=None`
        # (a unit test exercising the counter directly) must not become the one
        # the shutdown hook then drains, or the serving app is left with a
        # stranger's drain state.
        if app is not None:
            _CURRENT = self
        self._in_flight = 0
        # Created lazily, inside the running loop. asyncio.Event binds to the
        # loop that first awaits it, and this object is constructed during app
        # assembly -- which is not necessarily the loop that ends up serving
        # it, as the test suite and any process supervisor that reuses an app
        # object both demonstrate.
        self._idle: asyncio.Event | None = None
        self._idle_loop: asyncio.AbstractEventLoop | None = None
        self._draining = False
        self._timeout = timeout

    @property
    def draining(self) -> bool:
        return self._draining

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def _idle_event(self) -> asyncio.Event:
        """The idle event, bound to the loop that is running right now.

        Starlette builds the middleware stack once per app and reuses it, so
        this instance can outlive the loop it was first used on. asyncio.Event
        refuses to be awaited from a different loop, so the cached one is
        dropped when the loop changes rather than raising at shutdown — which is
        the worst possible moment to discover it.
        """
        loop = asyncio.get_running_loop()
        if self._idle is None or self._idle_loop is not loop:
            self._idle = asyncio.Event()
            self._idle_loop = loop
            if self._in_flight == 0:
                self._idle.set()
        return self._idle

    def begin_drain(self) -> None:
        self._draining = True

    def end_drain(self) -> None:
        """Clear the drain flag at startup.

        Draining is a property of a process lifetime, not of the object: a
        fresh process is not draining. Starlette also builds the middleware
        stack once per app and reuses it, so without this a drain triggered by
        one shutdown would still be set for the next startup -- which is exactly
        what happens under a test client and would be a latent bug behind any
        process supervisor that reuses an app object.
        """
        self._draining = False
        if self._in_flight == 0 and self._idle is not None:
            self._idle.set()

    async def wait_for_idle(self) -> bool:
        """Block until nothing is in flight. False if the timeout expired."""
        try:
            await asyncio.wait_for(self._idle_event().wait(), timeout=self._timeout)
            return True
        except TimeoutError:
            return False

    async def dispatch(self, request, call_next):  # type: ignore[no-untyped-def]
        if self._draining and request.url.path not in DRAIN_EXEMPT_PATHS:
            # Probes and health must keep answering, or the pod is killed by the
            # liveness probe while it is draining instead of being removed from
            # the service politely.
            return Response(
                content="draining",
                status_code=503,
                headers={"Retry-After": "5", "Connection": "close"},
                media_type="text/plain",
            )

        idle = self._idle_event()
        self._in_flight += 1
        idle.clear()
        try:
            return await call_next(request)
        finally:
            self._in_flight -= 1
            if self._in_flight == 0:
                idle.set()


#: The most recently constructed DrainMiddleware, for the shutdown hook.
_CURRENT: "DrainMiddleware | None" = None


def current_drain() -> "DrainMiddleware | None":
    return _CURRENT


#: Paths that must answer while draining, or the orchestration breaks: the
#: liveness probe kills a pod that looks dead, and readiness is how the load
#: balancer is told to stop sending it traffic.
DRAIN_EXEMPT_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})
