"""Request middleware: unique request IDs + latency headers on every response."""

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
