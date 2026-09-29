"""FastAPI application: /v1/chat, /v1/rag/*, admin + health endpoints."""

import asyncio
import json
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aegis.api.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from aegis.budget import BudgetExceeded
from aegis.config import Settings, get_settings
from aegis.gateway import Gateway, build_gateway
from aegis.metrics import metrics
from aegis.providers.registry import AllProvidersDown
from aegis.rag.service import RagPersistError, rag_service
from aegis.ratelimit import RateLimitExceeded, SlidingWindowLimiter
from aegis.security import admin_session
from aegis.security.admin_session import AdminAuthError
from aegis.security.auth import Authenticator, Tenant

STATE: dict = {}

def _login_redis():
    """Best-effort Redis handle for the login limiter.

    Returns ``None`` on any failure, which downgrades the limiter to
    per-process. That is a real weakening, so it is surfaced in the response and
    the health of it is asserted in tests rather than assumed.
    """
    try:
        import redis as _redis

        from aegis.config import get_settings as _gs

        url = _gs().redis_url
        return _redis.from_url(url, socket_connect_timeout=1) if url else None
    except Exception:  # noqa: BLE001
        return None


def _client_key(request: Request) -> str:
    """A best-effort source address for rate limiting.

    Only meaningful behind a proxy that sets X-Forwarded-For, and
    ``proxy_headers`` is deliberately not trusted by default, so this is a
    limiter, not an authentication control.
    """
    return (request.client.host if request.client else "unknown") or "unknown"

#: Credential-stuffing brake on `POST /admin/login`. The portal password is the
#: one credential in this system that is a single shared secret with no scope
#: and no lockout, so an unthrottled login form is a guessing oracle pointed at
#: the controls that can pause every tenant. Per-source and per-(source, id)
#: windows: the first stops one host spraying, the second stops one id being
#: sprayed from a botnet. Redis-backed so the limit is fleet-wide, not per-pod.
_LOGIN_LIMITER = SlidingWindowLimiter(limit_per_min=10, redis_client=_login_redis())

def _settings() -> Settings:
    """The Settings the running gateway was actually built from.

    `get_settings()` is lru_cached and re-reads the environment, so calling it
    here could hand the routes a *different* Settings than the gateway has —
    and a different admin session key means a cookie the routes refuse to
    verify, with no error anywhere to explain it.
    """
    settings = STATE.get("settings")
    if settings is None:
        settings = get_settings()
        STATE["settings"] = settings
    return settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    if "gateway" not in STATE:
        settings: Settings = get_settings()
        gateway = await build_gateway(settings)
        STATE["gateway"] = gateway
        STATE["settings"] = settings
        STATE["authenticator"] = Authenticator(settings)
        rag_service.configure(settings.database_url)
        try:
            rag_service.configure_embeddings(settings.embed_provider, settings.embed_model)
        except ValueError:
            pass
    else:
        # reuse test-injected gateway (pytest fixtures)
        if "settings" not in STATE:
            STATE["settings"] = STATE["gateway"].settings
    yield
    try:
        await STATE["gateway"].aclose()
    except Exception:  # noqa: BLE001,S110
        pass


app = FastAPI(
    title="AEGIS Gateway",
    version="0.1.0",
    description=(
        "Secure LLM gateway: prompt-injection defense, PII vault with "
        "re-identification, hash-chained audit log, hybrid RAG, eval-gated CI."
    ),
    lifespan=lifespan,
)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Console assets are served from disk, not a CDN. That keeps the dashboard
# working on an air-gapped network, and it lets the CSP forbid inline script and
# style outright instead of carving out 'unsafe-inline' for a framework's sake.
STATIC_DIR = Path(__file__).parent.parent / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(AllProvidersDown)
async def _providers_down(request: Request, exc: AllProvidersDown):  # type: ignore[no-untyped-def]
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=503,
        content={"detail": "all providers unavailable, retry shortly"},
        headers={"x-request-id": request.headers.get("x-request-id", "")},
    )


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
    # Never leak internals or keys: generic shape, request-id for log lookup.
    # HTTPExceptions (401/403/429/...) keep their own status — re-raise them.
    if isinstance(exc, HTTPException):
        raise exc
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=500,
        content={"detail": "internal error"},
        headers={"x-request-id": request.headers.get("x-request-id", "")},
    )


# --- schemas -----------------------------------------------------------------


class Message(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    # Bounded: an unbounded `content` let a client post a single 5 MB message,
    # which the gateway then regex-scanned and json-dumped for the cache key
    # before forwarding — cheap amplification, and the budget preflight's
    # len/4 token estimate under-counts the real provider bill.
    content: str = Field(max_length=32_000)


class ChatRequest(BaseModel):
    messages: list[Message] = Field(min_length=1, max_length=64)
    max_tokens: int = Field(default=400, ge=1, le=4000)
    use_cache: bool = True


class IngestRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    source: str = Field(min_length=1, max_length=256)


class RagQueryRequest(BaseModel):
    question: str = Field(min_length=1, max_length=8_000)


class RagDeleteRequest(BaseModel):
    source: str = Field(min_length=1, max_length=256)


# --- dependencies --------------------------------------------------------------


def get_tenant(request: Request) -> Tenant:
    auth: Authenticator = STATE["authenticator"]
    return auth.authenticate(request)


def get_gateway() -> Gateway:
    return STATE["gateway"]


def _apply_quota_headers(response: Response, result: dict) -> None:
    quota = result.get("rate_limit") or {}
    if "remaining" in quota:
        response.headers["X-RateLimit-Remaining"] = str(quota["remaining"])
    if "limit" in quota:
        response.headers["X-RateLimit-Limit"] = str(quota["limit"])


def _reject_client_system_prompt(gateway: Gateway, messages: list[Message]) -> None:
    """Opt-in hardening via AEGIS_ALLOW_CLIENT_SYSTEM_PROMPT=false.

    Default is permissive, because OpenAI-compatible clients legitimately send a
    system prompt and AEGIS is a drop-in proxy. This flag is *policy*, not
    protection: every turn is scanned and PII-redacted regardless of role, so a
    client-supplied system prompt is never a way past the gate. Set it to false
    when the gateway owns the system prompt (e.g. RAG-only deployments)."""
    if gateway.settings.allow_client_system_prompt:
        return
    if any(m.role == "system" for m in messages):
        raise HTTPException(
            status_code=400,
            detail=("client-supplied 'system' messages are disabled on this gateway "
                    "(AEGIS_ALLOW_CLIENT_SYSTEM_PROMPT=false)"),
        )


def _debug_enabled(gateway: Gateway) -> bool:
    """Outbound payload preview: development and test only.

    Returning the sanitized payload the provider received is the single most
    useful thing an operator can see — it is the difference between claiming PII
    was masked and showing it — but it is diagnostic output, not product
    surface, so production never emits it regardless of who is asking.
    """
    return gateway.settings.env != "production"


# --- routes ---------------------------------------------------------------------


@app.post("/v1/chat")
async def chat(
    body: ChatRequest,
    response: Response,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> dict:
    if "chat" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'chat' required")
    _reject_client_system_prompt(gateway, body.messages)
    try:
        result = await gateway.handle_chat(
            tenant_id=tenant.id,
            messages=[m.model_dump() for m in body.messages],
            max_tokens=body.max_tokens,
            use_cache=body.use_cache,
            debug=_debug_enabled(gateway),
        )
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc),
                            headers={"Retry-After": str(exc.retry_after),
                                     "X-RateLimit-Remaining": "0"}) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    # scope check happens after auth; blocked injections are still audited responses
    _apply_quota_headers(response, result)
    completion = result["completion"] or {}
    return {
        "answer": result["answer"],
        "blocked": result["blocked"],
        "injection": result["injection"],
        "usage": completion.get("input_tokens"),
        "output_tokens": completion.get("output_tokens"),
        "latency_ms": completion.get("latency_ms"),
        "model": completion.get("model"),
        "provider": completion.get("provider"),
        "routing": result.get("routing"),
        "audit_seq": result.get("audit_seq"),
        "pii_masked": result.get("pii_masked", []),
        "cached": result.get("cached", False),
        "outbound": result.get("outbound"),
        # Present only when an operator paused the tenant or pulled the kill
        # switch. It is what lets a client tell "an administrator stopped this"
        # apart from "AEGIS blocked this for safety" — two very different things
        # to tell a user, and the second must never be phrased as the first.
        "operator": result.get("operator"),
    }


@app.post("/v1/rag/ingest")
async def rag_ingest(
    body: IngestRequest,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> dict:
    if "rag" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'rag' required")
    metrics.inc("aegis_rag_ingests_total", tenant=tenant.id)
    # Document lifecycle is audited too: "which document did the AI answer from,
    # and who added it" is exactly the question an auditor asks, and the answer
    # must be in the same tamper-evident chain as the answers themselves.
    result = await asyncio.to_thread(rag_service.ingest, body.text, body.source, tenant.id)
    result["audit_seq"] = await gateway.audit_async(tenant.id, "doc_ingested", {
        "source": body.source,
        "chunks": result.get("chunks_indexed", 0),
        "index_size": result.get("index_size", 0),
        "chars": len(body.text),
    })
    return result


@app.get("/v1/rag/documents")
async def rag_documents(tenant: Tenant = Depends(get_tenant)) -> dict:
    """Inventory of what this tenant's AI can answer from.

    Tenant-scoped by construction: the retriever map is keyed by tenant, so this
    can only ever enumerate the caller's own documents.
    """
    if "rag" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'rag' required")
    return await asyncio.to_thread(rag_service.list_documents, tenant.id)


@app.post("/v1/rag/delete")
async def rag_delete(
    body: RagDeleteRequest,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> dict:
    if "rag" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'rag' required")
    try:
        result = await asyncio.to_thread(rag_service.delete_document, tenant.id, body.source)
    except RagPersistError as exc:
        # The durable copy could not be removed, so the in-memory index was left
        # untouched on purpose: reporting success here would be a lie that a
        # restart would expose by resurrecting the document.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    metrics.inc("aegis_rag_deletes_total", tenant=tenant.id)
    result["audit_seq"] = await gateway.audit_async(tenant.id, "doc_deleted", {
        "source": body.source,
        "chunks": result.get("chunks_removed", 0),
        "index_size": result.get("index_size", 0),
    })
    return result


@app.post("/v1/rag/query")
async def rag_query(
    body: RagQueryRequest,
    response: Response,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> dict:
    if "rag" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'rag' required")

    ctx = rag_service.prepare(body.question, tenant.id)
    try:
        result = await gateway.handle_chat(
            tenant_id=tenant.id,
            messages=[
                {"role": "system", "content": ctx.system_prompt},
                {"role": "user", "content": body.question},
            ],
            max_tokens=600,
            debug=_debug_enabled(gateway),
        )
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc),
                            headers={"Retry-After": str(exc.retry_after),
                                     "X-RateLimit-Remaining": "0"}) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    citations = ctx.citations if not result["injection"]["blocked"] else []
    _apply_quota_headers(response, result)
    completion = result["completion"] or {}
    return {
        "answer": result["answer"],
        "blocked": result["blocked"],
        "injection": result["injection"],
        "citations": citations,
        "retrieved": len(citations),
        "routing": result.get("routing"),
        "provider": completion.get("provider"),
        "audit_seq": result.get("audit_seq"),
        "pii_masked": result.get("pii_masked", []),
        "outbound": result.get("outbound"),
        "operator": result.get("operator"),
    }


@app.post("/v1/chat/stream")
async def chat_stream(
    body: ChatRequest,
    response: Response,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
):
    if "chat" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'chat' required")
    _reject_client_system_prompt(gateway, body.messages)

    try:
        stream = gateway.stream_chat(
            tenant_id=tenant.id,
            messages=[m.model_dump() for m in body.messages],
            max_tokens=body.max_tokens,
            use_cache=body.use_cache,
            debug=_debug_enabled(gateway),
        )
        # Buffer first event to surface 429/402 before SSE headers commit.
        first: dict | None = None
        async for ev in stream:  # type: ignore[union-attr]
            first = ev
            break

        async def event_gen():
            def sse(obj: dict) -> str:
                return f"data: {json.dumps(obj)}\n\n"

            nonlocal first
            if first is None:
                yield "data: [DONE]\n\n"
                return
            if first.get("type") == "blocked":
                yield sse({"blocked": True, "injection": first["injection"],
                           "answer": first["answer"],
                           "pii_masked": first.get("pii_masked", []),
                           "outbound": first.get("outbound")})
                yield "data: [DONE]\n\n"
                return
            if first.get("type") == "delta":
                evt: dict = {"delta": first["delta"], "index": first.get("index", 0)}
                if "ttft_ms" in first:
                    evt["ttft_ms"] = first["ttft_ms"]
                yield sse(evt)
            elif first.get("type") == "done":
                yield sse({"done": True,
                           **{k: v for k, v in first.items() if k != "type"}})
                yield "data: [DONE]\n\n"
                return
            async for ev2 in stream:  # type: ignore[union-attr]
                if ev2.get("type") == "delta":
                    evt2: dict = {"delta": ev2["delta"], "index": ev2.get("index", 0)}
                    if "ttft_ms" in ev2:
                        evt2["ttft_ms"] = ev2["ttft_ms"]
                    yield sse(evt2)
                elif ev2.get("type") == "done":
                    yield sse({"done": True,
                               **{k: v for k, v in ev2.items() if k != "type"}})
                    yield "data: [DONE]\n\n"
                    return
                elif ev2.get("type") == "blocked":
                    yield sse({"blocked": True, "injection": ev2["injection"],
                               "answer": ev2["answer"]})
                    yield "data: [DONE]\n\n"
                    return
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc),
                            headers={"Retry-After": str(exc.retry_after),
                                     "X-RateLimit-Remaining": "0"}) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    quota = (first or {}).get("rate_limit") or {}
    quota_headers = {}
    if "remaining" in quota:
        quota_headers["X-RateLimit-Remaining"] = str(quota["remaining"])
    if "limit" in quota:
        quota_headers["X-RateLimit-Limit"] = str(quota["limit"])
    return StreamingResponse(event_gen(), media_type="text/event-stream", headers=quota_headers)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict:
    """Readiness: boot chain intact + at least one provider (echo counts).

    No auth so K8s probes stay simple. Returns 503 when not ready so the
    pod is removed from service without failing liveness. Uses the O(1)
    tail probe, not a full chain verify — probe cost stays flat as the
    audit log grows (M13).
    """
    gateway: Gateway | None = STATE.get("gateway")
    if gateway is None:
        raise HTTPException(status_code=503, detail="starting")
    ok, msg = gateway.audit.probe()
    if not ok or not gateway.registry:
        raise HTTPException(status_code=503, detail=msg or "no providers")
    return {"status": "ready", "audit": msg}


@app.get("/metrics")
async def prometheus_metrics(tenant: Tenant = Depends(get_tenant)):
    # Authenticated, and tenant-scoped: `admin` callers see every series
    # (global dashboards keep working with an admin scrape token holding
    # `authorization: credentials:`); any other tenant sees only its own
    # `tenant="<id>"` series plus untagged globals. Without scoping, any
    # valid tenant token could read every tenant's usage — cross-tenant
    # disclosure through an observability side channel.
    from fastapi import Response

    body = metrics.render() if "admin" in tenant.scopes else metrics.render(tenant=tenant.id)
    return Response(content=body, media_type="text/plain; version=0.0.4")


async def _record_audit_read(
    gateway: Gateway,
    caller: Tenant,
    scope_filter: str,
    limit: int,
    event: str,
    with_payload: bool,
) -> None:
    """Record the fact that the audit trail was read.

    A log nobody can see is not evidence, and a log only an operator reads is not
    a control either: reading the chain is an access to everything in it, and the
    one question a compliance reviewer asks about a tamper-evident store is who
    looked. A failed read is not recorded — it did not disclose anything.

    The payload records the *shape* of the read (whose records, how many, with
    or without payloads) and never the records themselves, so reading the log
    cannot balloon it.
    """
    cross_tenant = bool(scope_filter) and scope_filter != caller.id
    await asyncio.to_thread(
        gateway.audit.append,
        caller.id,
        "admin_audit_read",
        {
            "scope": scope_filter or "(whole gateway)",
            "cross_tenant": cross_tenant,
            "limit": limit,
            "event_filter": event or None,
            "with_payload": bool(with_payload),
        },
    )


@app.get("/admin/audit")
async def admin_audit(
    limit: int = 50,
    tenant: str = "",
    event: str = "",
    include_payload: bool = True,
    caller: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> dict:
    """Read the tamper-evident trail back, newest window first.

    The chain was always verifiable but never *readable* — a product whose pitch
    is "prove what the AI said" has to let someone actually look. Every row comes
    back with its signature and chain link re-checked, and with the payload
    decrypted when payload copies are enabled.

    Tenant scoping: an `admin`-scoped caller may pass `tenant=` to audit one
    tenant, or omit it to see the whole gateway. Callers without `admin` are
    pinned to their own records — they can always prove their own history, and
    can never enumerate anyone else's.
    """
    if "admin" in caller.scopes:
        scope_filter = tenant
    else:
        if tenant and tenant != caller.id:
            raise HTTPException(status_code=403, detail="scope 'admin' required to read other tenants")
        scope_filter = caller.id

    limit = max(1, min(limit, 500))
    await _record_audit_read(gateway, caller, scope_filter, limit, event, include_payload)
    data = await asyncio.to_thread(
        gateway.audit.tail_records,
        limit=limit,
        tenant=scope_filter,
        event=event,
        with_payload=include_payload,
    )
    data["caller"] = caller.id
    data["scoped_to_tenant"] = scope_filter or None
    return data


@app.get("/admin/audit/export")
async def admin_audit_export(
    limit: int = 500,
    tenant: str = "",
    event: str = "",
    caller: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> Response:
    """Download the verified window as NDJSON for an auditor's own tooling."""
    if "admin" not in caller.scopes:
        raise HTTPException(status_code=403, detail="scope 'admin' required")
    limit = max(1, min(limit, 500))
    await _record_audit_read(gateway, caller, tenant, limit, event, with_payload=False)
    data = await asyncio.to_thread(
        gateway.audit.tail_records, limit=limit, tenant=tenant, event=event
    )
    body = "\n".join(json.dumps(r, separators=(",", ":")) for r in data["records"])
    return Response(
        content=body + ("\n" if body else ""),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="aegis-audit-export.jsonl"',
            "X-Aegis-Chain-Head": data["chain"]["head"],
            "X-Aegis-Records": str(data["count"]),
            "Cache-Control": "no-store",
        },
    )


@app.get("/admin/status")
async def admin_status(
    tenant: Tenant = Depends(get_tenant), gateway: Gateway = Depends(get_gateway)
) -> dict:
    # Global ops view (all breakers, cache totals, chain length) — admin only.
    if "admin" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'admin' required")
    ok, chain_msg = gateway.audit.verify()
    return {
        "tenant": tenant.id,
        "audit_chain": {"intact": ok, "detail": chain_msg, "length": gateway.audit.seq},
        "cache": gateway.cache.stats(),
        "breakers": [b.snapshot() for _, b in gateway.registry.values()],
        "budget": gateway.budget.usage(tenant.id),
    }


def _require_admin(tenant: Tenant) -> None:
    if "admin" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'admin' required")


# --------------------------------------------------------- admin sessions --

def _admin_creds(settings: Settings) -> tuple[str, str] | None:
    """The portal login, or ``None`` when only bearer tokens are accepted."""
    if not settings.admin_username or not settings.admin_password:
        return None
    return settings.admin_username, settings.admin_password


def _verify_admin_session(request: Request, settings: Settings) -> str | None:
    """The signed-in username for this request, or ``None``.

    Always passes the credential fingerprint, so a password change ends every
    live session. A caller that forgets the fingerprint would silently make the
    binding decorative, so there is one function and both call sites use it.
    """
    token = request.cookies.get(admin_session.COOKIE)
    if not token:
        return None
    key, fingerprint = admin_session_credentials(settings)
    return admin_session.verify(token, key, fingerprint=fingerprint)


def admin_session_credentials(settings: Settings) -> tuple[str, str | None]:
    """The session key plus the fingerprint the current credential implies.

    Verifying a cookie without the fingerprint would make the binding
    decorative, so every verification path goes through here.
    """
    key = _admin_session_key(settings)
    creds = _admin_creds(settings)
    fingerprint = (
        admin_session.credential_fingerprint(creds[0], creds[1], key) if creds else None
    )
    return key, fingerprint


def _admin_session_key(settings: Settings) -> str:
    # Fall back to the audit key so a deployment that has not set the dedicated
    # one still gets working, signed sessions rather than a silent no-op.
    return settings.admin_session_key or settings.audit_hmac_key or "aegis-admin-dev"


def require_admin_portal(request: Request) -> str:
    """Authorize an admin call from either credential, and say which was used.

    A browser sends the session cookie; a script sends the scoped bearer token.
    Both are accepted on the same routes so monitoring does not need a cookie
    jar, and so turning the portal login on cannot break an existing scraper.
    """
    settings = _settings()
    if _admin_creds(settings) is None:
        # No portal login configured: fall back to the pre-existing behaviour.
        _require_admin(get_tenant(request))
        return "bearer"

    username = _verify_admin_session(request, settings)
    if username:
        return username

    # No valid session. Fall through to a bearer token if one was supplied, so a
    # script is not forced to log in.
    if request.headers.get("authorization"):
        _require_admin(get_tenant(request))
        return "bearer"

    raise HTTPException(
        status_code=401,
        detail="admin session required",
        headers={"WWW-Authenticate": "Cookie"},
    )


class AdminLogin(BaseModel):
    username: str = Field(default="", max_length=200)
    password: str = Field(default="", max_length=400)


@app.post("/admin/login")
async def admin_login(payload: AdminLogin, response: Response, request: Request) -> dict:
    """Exchange an id and password for a signed session cookie.

    Rate limited per source and per (source, id). A wrong guess is counted, a
    correct one clears the window — so a genuine operator who fumbles their
    password twice is not the one who gets locked out, while a spray of guesses
    from anywhere runs out of budget quickly.
    """
    settings = _settings()
    creds = _admin_creds(settings)
    if creds is None:
        raise HTTPException(
            status_code=404,
            detail="portal login is not configured; use an admin-scoped bearer token",
        )

    source = _client_key(request)
    windows = (f"admin-login:{source}", f"admin-login:{source}:{payload.username[:64]}")
    for window in windows:
        verdict = _LOGIN_LIMITER.check(window)
        if not verdict.allowed:
            raise HTTPException(
                status_code=429,
                detail="too many login attempts; try again shortly",
                headers={"Retry-After": str(verdict.retry_after)},
            )

    session_key, _ = admin_session_credentials(settings)
    try:
        admin_session.check_credentials(payload.username, payload.password, *creds)
    except AdminAuthError:
        # Deliberately vague, and deliberately not audited with the attempted
        # username: a failed login is not evidence, and logging the guess would
        # turn the audit chain into a password oracle.
        raise HTTPException(status_code=401, detail="invalid id or password") from None

    # A correct login clears the window, or a typo would slowly spend an
    # operator's budget for them.
    for window in windows:
        _LOGIN_LIMITER.reset(window)

    response.set_cookie(
        value=admin_session.sign(
            payload.username,
            session_key,
            settings.admin_session_ttl,
            fingerprint=admin_session.credential_fingerprint(
                payload.username, payload.password, session_key
            ),
        ),
        **admin_session.cookie_kwargs(
            secure=settings.env == "production", max_age=settings.admin_session_ttl
        ),
    )
    return {"authenticated": True, "user": payload.username}


@app.post("/admin/logout")
async def admin_logout(response: Response) -> dict:
    settings = _settings()
    response.delete_cookie(**admin_session.delete_cookie_kwargs(
        secure=settings.env == "production"
    ))
    return {"authenticated": False}


@app.get("/admin/session")
async def admin_session_state(request: Request) -> dict:
    """Who the portal thinks you are, and whether a login is even available."""
    settings = _settings()
    creds = _admin_creds(settings)
    username = _verify_admin_session(request, settings)
    demo = bool(
        creds
        and creds[0] == admin_session.DEMO_USERNAME
        and creds[1] == admin_session.DEMO_PASSWORD
    )
    return {
        "authenticated": username is not None,
        "user": username,
        "login_available": creds is not None,
        # The portal says so in the UI rather than letting an operator believe a
        # published default is a real credential.
        "demo_credentials": demo,
    }


@app.get("/admin/overview")
async def admin_overview(
    tenant: Tenant = Depends(get_tenant), gateway: Gateway = Depends(get_gateway)
) -> dict:
    """Fleet Overview: is anything wrong?

    Every counter here is in-process and per-pod, so the payload reports
    `counters_since` (the boot timestamp) alongside the numbers. A view that
    drew these as a 24-hour chart would be inventing history it does not have —
    the honest presentation is "cumulative since boot", labelled as such.
    """
    _require_admin(tenant)
    ok, chain_msg = gateway.audit.verify()
    requests = metrics.total("aegis_requests_total")
    blocked = metrics.total("aegis_injection_blocked_total")
    soft = metrics.total("aegis_injection_softblocked_total")
    return {
        "generated_at": time.time(),
        # The window every counter below describes. The admin view shows it.
        "counters_since": time.time() - metrics.uptime_seconds(),
        "uptime_seconds": metrics.uptime_seconds(),
        "counters_cumulative": True,
        "requests": requests,
        "blocked_hard": blocked,
        "blocked_soft": soft,
        "blocked_total": blocked + soft,
        "block_rate": round((blocked + soft) / requests, 4) if requests else 0.0,
        "rate_limited": metrics.total("aegis_rate_limited_total"),
        "provider_failures": metrics.total("aegis_provider_failures_total"),
        "tokens": metrics.total("aegis_tokens_total"),
        "cost_usd": round(metrics.total("aegis_cost_usd_total"), 4),
        "cache": gateway.cache.stats(),
        "breakers": [b.snapshot() for _, b in gateway.registry.values()],
        "audit_chain": {"intact": ok, "detail": chain_msg, "length": gateway.audit.seq,
                        "head": gateway.audit.head},
        "tenants": metrics.tenant_totals(),
    }


@app.get("/admin/tenants")
async def admin_tenants(
    tenant: Tenant = Depends(get_tenant), gateway: Gateway = Depends(get_gateway)
) -> dict:
    """Every configured tenant: scopes, budget burn, document count, activity.

    Read-only by design. Key rotation stays in scripts/gen_tenant.py, where it
    is auditable in a shell history and cannot be CSRF'd from a browser.
    """
    _require_admin(tenant)
    totals = metrics.tenant_totals()
    rows: list[dict] = []
    for tid, (_key_hash, scopes) in sorted(gateway.settings.tenant_map().items()):
        usage = gateway.budget.usage(tid)
        try:
            docs = rag_service.list_documents(tid).get("documents", [])
        except Exception:  # noqa: BLE001 — a per-tenant store error must not blank the fleet view
            docs = []
        activity = totals.get(tid, {})
        used, limit = usage["used"], max(1, usage["limit"])
        rows.append({
            "id": tid,
            "scopes": sorted(scopes),
            "requests": activity.get("requests", 0.0),
            "blocked": activity.get("blocked", 0.0) + activity.get("soft_blocked", 0.0),
            "cost_usd": round(activity.get("cost_usd", 0.0), 4),
            "budget_used": used,
            "budget_limit": usage["limit"],
            "budget_pct": round(used / limit, 4),
            "documents": len(docs),
        })
    return {"tenants": rows, "count": len(rows)}


# ------------------------------------------------------- operator controls --
#
# The admin portal is meant to be self-sufficient: pausing a noisy tenant or
# holding a broken provider open during an incident should not require a shell,
# a kubectl exec, or a Redis CLI. Every action below is one HTTP call the portal
# makes, and every one of them is written into the same signed audit chain as
# ordinary traffic — because "who paused what, and when" is a fact the product
# will be asked for.

#: Failed break-glass attempts per actor, and when each was first seen. Bounded
#: and in-process on purpose: a step-up secret is worth little against a script
#: that can try a thousand passwords a second, and this refuses the *endpoint*
#: rather than merely slowing a guess.
_breakglass_failures: dict[str, list[float]] = {}


def _check_breakglass(presented: str, actor: str, settings: Settings) -> bool:
    """True when the break-glass secret is correct and not rate-limited out.

    Both halves are computed, never short-circuited, so a wrong secret and a
    right one take the same time. The limiter is checked first and its failure
    also costs a constant-time comparison, so "you are locked out" and "wrong
    password" are not distinguishable by timing either.
    """
    now = time.time()
    window = now - 300.0
    attempts = [t for t in _breakglass_failures.get(actor, []) if t > window]
    locked = len(attempts) >= settings.breakglass_attempts
    matches = secrets.compare_digest(
        (presented or "").encode(), (settings.breakglass_password or "").encode()
    )
    if locked or not matches:
        attempts.append(now)
        _breakglass_failures[actor] = attempts
        return False
    _breakglass_failures.pop(actor, None)
    return True


def _reset_breakglass() -> None:
    """Test hook."""
    _breakglass_failures.clear()

class KillSwitch(BaseModel):
    on: bool
    # Presented when the deployment configures a break-glass secret. Required
    # only to switch traffic *off*; turning it back on must never be the harder
    # operation, or an incident ends with a gateway nobody can restart.
    breakglass: str = ""


class BreakerState(BaseModel):
    state: str = Field(pattern="^(open|closed|auto)$")


def _known_tenant(gateway: Gateway, tenant_id: str) -> str:
    """Refuse to act on a tenant that does not exist.

    Without this, a typo silently creates a pause for a tenant nobody has, and
    the operator believes they have contained an incident.
    """
    if tenant_id not in gateway.settings.tenant_map():
        raise HTTPException(status_code=404, detail=f"unknown tenant {tenant_id!r}")
    return tenant_id


def _known_provider(gateway: Gateway, name: str) -> str:
    if name not in gateway.registry:
        raise HTTPException(status_code=404, detail=f"unknown provider {name!r}")
    return name


def _audit_control(gateway: Gateway, actor: str, action: str, detail: dict) -> None:
    gateway.audit.append("admin", f"control_{action}",
                         {"actor": actor, "via": "admin-portal", **detail})


@app.get("/admin/controls")
async def admin_controls(
    gateway: Gateway = Depends(get_gateway), actor: str = Depends(require_admin_portal)
) -> dict:
    """The whole control plane, plus which tenants it can be aimed at."""
    snapshot = gateway.ops.snapshot()
    settings = _settings()
    return {
        **snapshot,
        "actor": actor,
        "tenants": sorted(gateway.settings.tenant_map()),
        "providers": sorted(gateway.registry),
        # So the UI can say whether pulling the kill switch needs a second
        # secret, rather than discovering it with a 403 mid-incident.
        "breakglass_required": bool(settings.breakglass_password),
    }


@app.post("/admin/controls/kill")
async def admin_kill(
    payload: KillSwitch, gateway: Gateway = Depends(get_gateway),
    actor: str = Depends(require_admin_portal),
) -> dict:
    """Refuse everything, for everyone. The panic button.

    Stopping traffic needs the break-glass secret *in the moment*, on top of the
    portal session, so that holding a working session is not the same thing as
    being able to halt every tenant. Restoring traffic never needs it: an
    incident must not end with a gateway nobody can switch back on.

    Both the attempt and its refusal are audited. An operator reaching for the
    kill switch and a stranger doing the same from a hijacked session are very
    different events and only one of them is the one you want in the record.
    """
    settings = _settings()
    if payload.on and settings.breakglass_password:
        ok_attempt = _check_breakglass(payload.breakglass, actor, settings)
        if not ok_attempt:
            _audit_control(gateway, actor, "kill_refused_breakglass",
                           {"reason": "bad or missing break-glass secret"})
            raise HTTPException(
                status_code=403,
                detail="the break-glass secret is required to refuse all traffic",
            )
        _audit_control(gateway, actor, "kill_on_breakglass", {})
    else:
        _audit_control(gateway, actor, "kill_on" if payload.on else "kill_off", {})
    gateway.ops.set_kill(payload.on)
    return gateway.ops.snapshot()


@app.post("/admin/controls/tenant/{tenant_id}/pause")
async def admin_pause_tenant(
    tenant_id: str, gateway: Gateway = Depends(get_gateway),
    actor: str = Depends(require_admin_portal),
) -> dict:
    _known_tenant(gateway, tenant_id)
    gateway.ops.pause(tenant_id)
    _audit_control(gateway, actor, "tenant_paused", {"tenant": tenant_id})
    return gateway.ops.snapshot()


@app.post("/admin/controls/tenant/{tenant_id}/resume")
async def admin_resume_tenant(
    tenant_id: str, gateway: Gateway = Depends(get_gateway),
    actor: str = Depends(require_admin_portal),
) -> dict:
    _known_tenant(gateway, tenant_id)
    gateway.ops.resume(tenant_id)
    _audit_control(gateway, actor, "tenant_resumed", {"tenant": tenant_id})
    return gateway.ops.snapshot()


@app.post("/admin/controls/tenant/{tenant_id}/allow")
async def admin_allow_tenant(
    tenant_id: str, gateway: Gateway = Depends(get_gateway),
    actor: str = Depends(require_admin_portal),
) -> dict:
    """Waive the soft band for one tenant.

    The hard band is not waivable and there is deliberately no endpoint that
    could waive it. This is the whole reason an allowlist is safe to hand to an
    operator: it can stop a known-noisy caller being refused, and it cannot
    become a switch that turns injection detection off.
    """
    _known_tenant(gateway, tenant_id)
    gateway.ops.allow(tenant_id)
    _audit_control(gateway, actor, "tenant_softband_allowed", {"tenant": tenant_id})
    return gateway.ops.snapshot()


@app.post("/admin/controls/tenant/{tenant_id}/deny")
async def admin_deny_tenant(
    tenant_id: str, gateway: Gateway = Depends(get_gateway),
    actor: str = Depends(require_admin_portal),
) -> dict:
    _known_tenant(gateway, tenant_id)
    had = gateway.ops.deny(tenant_id)
    _audit_control(gateway, actor, "tenant_softband_waiver_revoked",
                   {"tenant": tenant_id, "had_waiver": had})
    return {**gateway.ops.snapshot(), "revoked": had}


@app.post("/admin/controls/breaker/{name}")
async def admin_breaker(
    name: str, payload: BreakerState, gateway: Gateway = Depends(get_gateway),
    actor: str = Depends(require_admin_portal),
) -> dict:
    """Hold a provider's circuit, or hand it back to the automatic threshold."""
    _known_provider(gateway, name)
    gateway.ops.set_breaker(name, payload.state)
    _audit_control(gateway, actor, "breaker_override",
                   {"provider": name, "state": payload.state})
    return gateway.ops.snapshot()


@app.get("/admin/attacks")
async def admin_attacks(    tenant: Tenant = Depends(get_tenant), gateway: Gateway = Depends(get_gateway)
) -> dict:
    """Blocked and soft-refused requests, newest first.

    The band is derived from the signed *event name*, not from the payload. That
    is deliberate: `injection_blocked` and `injection_flagged` are both inside
    the HMAC, so "a hard block happened here" stays provable on a chain written
    with payload copies switched off. Reading `band` out of the payload instead
    would make the most important column depend on an optional setting.

    Score and labels come from the payload, so they are present only when
    AEGIS_AUDIT_ENCRYPT_KEY is set. The response says which case you are in
    instead of rendering an empty score as though it were 0.0.

    There is no "add to blocklist" action on purpose: a rule written from a
    payload nobody reviewed is how you refuse a legitimate customer.
    """
    _require_admin(tenant)
    rows: list[dict] = []
    for event, band in (("injection_blocked", "hard"), ("injection_flagged", "soft")):
        window = gateway.audit.tail_records(limit=500, event=event, with_payload=True)
        for rec in window["records"]:
            payload = rec.get("payload") or {}
            rows.append({
                "seq": rec["seq"],
                "ts": rec["ts"],
                "tenant": rec["tenant"],
                "request_id": rec["request_id"],
                "event": event,
                "band": band,
                "score": payload.get("score"),
                "labels": payload.get("labels") or [],
                "sig_ok": rec["sig_ok"],
                "payload_ok": rec["payload_ok"],
            })
    rows.sort(key=lambda r: r["ts"], reverse=True)
    hard = [r for r in rows if r["band"] == "hard"]
    soft = [r for r in rows if r["band"] == "soft"]
    return {
        "attacks": rows[:200],
        "count": len(rows),
        "hard_count": len(hard),
        "soft_count": len(soft),
        "scores_available": bool(gateway.audit.encrypt_key),
        "window_records": 500,
        "window_note": (
            "Band is read from the signed event name, so it holds even without "
            "payload copies. Score and labels need AEGIS_AUDIT_ENCRYPT_KEY. "
            "Window is the last 500 records per event; older attempts need an export."
        ),
    }


TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def _serve_template(name: str, transform: Callable[[str], str] | None = None) -> HTMLResponse:
    html_path = TEMPLATES_DIR / name
    if not html_path.exists():
        return HTMLResponse(
            f"<h1>Page not found</h1><p>Expected at templates/{name}</p>",
            status_code=500,
            headers={"Cache-Control": "no-store"},
        )
    html = html_path.read_text(encoding="utf-8")
    return HTMLResponse(
        transform(html) if transform else html,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/", include_in_schema=False)
async def root():
    """The pitch. The working product is a separate page at /dashboard, so a
    reader is never asked to care about the argument before they can touch
    the thing — and the console is never buried under marketing copy."""
    return _serve_template("landing.html")


DEMO_PLACEHOLDER = "__AEGIS_DEMO_SLOT__"


def _render_dashboard(html: str) -> str:
    """Substitute the demo key into the template — development only.

    /dashboard is unauthenticated, so a hardcoded key in the template is served
    to anyone who can reach the port. In production the token becomes an empty
    value and the page asks the user to paste their own key (the dashboard's own
    inline script flips the status pill when the field arrives empty).
    """
    gateway: Gateway | None = STATE.get("gateway")
    settings = gateway.settings if gateway is not None else get_settings()
    demo_key = "" if settings.env == "production" else settings.demo_api_key
    return html.replace(DEMO_PLACEHOLDER, demo_key)


@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    return _serve_template("dashboard.html", _render_dashboard)


@app.get("/admin", include_in_schema=False)
async def admin_console():
    """The fleet surface: Overview, Tenants, Chain, Attacks, Tour.

    The page shell is a static template like `/dashboard` — no tenant data, no
    chain contents, nothing rendered from a request. Every number on this page
    arrives from an `admin`-scoped JSON endpoint, so an unauthenticated visitor
    gets empty tables rather than a partial view of someone else's fleet. The
    split that matters is enforced server-side by scope, not by hiding tabs.
    """
    return _serve_template("admin.html", _render_dashboard)
