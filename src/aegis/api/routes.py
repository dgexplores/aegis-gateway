"""FastAPI application: /v1/chat, /v1/rag/*, admin + health endpoints."""

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

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
from aegis.ratelimit import RateLimitExceeded
from aegis.security.auth import Authenticator, Tenant

STATE: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    if "gateway" not in STATE:
        settings: Settings = get_settings()
        gateway = await build_gateway(settings)
        STATE["gateway"] = gateway
        STATE["authenticator"] = Authenticator(settings)
        rag_service.configure(settings.database_url)
        try:
            rag_service.configure_embeddings(settings.embed_provider, settings.embed_model)
        except ValueError:
            pass
    else:
        # reuse test-injected gateway (pytest fixtures)
        pass
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
    pod is removed from service without failing liveness.
    """
    gateway: Gateway | None = STATE.get("gateway")
    if gateway is None:
        raise HTTPException(status_code=503, detail="starting")
    ok, msg = gateway.audit.verify()
    if not ok or not gateway.registry:
        raise HTTPException(status_code=503, detail=msg or "no providers")
    return {"status": "ready", "audit": msg}


@app.get("/metrics")
async def prometheus_metrics(tenant: Tenant = Depends(get_tenant)):
    # Authenticated: series carry per-tenant labels (usage by tenant id),
    # which must not be world-readable. Scrape with a bearer token
    # (Prometheus `authorization: credentials:`) holding any valid tenant.
    from fastapi import Response

    return Response(content=metrics.render(), media_type="text/plain; version=0.0.4")


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


@app.get("/", include_in_schema=False)
async def root():
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/dashboard")


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
    html_path = Path(__file__).parent.parent / "templates" / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(
            _render_dashboard(html_path.read_text(encoding="utf-8")),
            headers={"Cache-Control": "no-store"},
        )
    return HTMLResponse(
        "<h1>Dashboard not found</h1><p>Expected at templates/dashboard.html</p>",
        status_code=500,
        headers={"Cache-Control": "no-store"},
    )
