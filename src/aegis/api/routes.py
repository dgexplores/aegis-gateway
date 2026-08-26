"""FastAPI application: /v1/chat, /v1/rag/*, admin + health endpoints."""

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from aegis.api.middleware import RequestContextMiddleware
from aegis.budget import BudgetExceeded
from aegis.config import Settings, get_settings
from aegis.gateway import Gateway, build_gateway
from aegis.metrics import metrics
from aegis.rag.service import rag_service
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


# --- schemas -----------------------------------------------------------------


class Message(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


class ChatRequest(BaseModel):
    messages: list[Message]
    max_tokens: int = Field(default=400, ge=1, le=4000)
    use_cache: bool = True


class IngestRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    source: str = Field(min_length=1, max_length=256)


class RagQueryRequest(BaseModel):
    question: str = Field(min_length=1, max_length=8_000)


# --- dependencies --------------------------------------------------------------


def get_tenant(request: Request) -> Tenant:
    auth: Authenticator = STATE["authenticator"]
    return auth.authenticate(request)


def get_gateway() -> Gateway:
    return STATE["gateway"]


# --- routes ---------------------------------------------------------------------


@app.post("/v1/chat")
async def chat(
    body: ChatRequest,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
) -> dict:
    if "chat" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'chat' required")
    try:
        result = await gateway.handle_chat(
            tenant_id=tenant.id,
            messages=[m.model_dump() for m in body.messages],
            max_tokens=body.max_tokens,
            use_cache=body.use_cache,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc),
                            headers={"Retry-After": str(exc.retry_after)}) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    # scope check happens after auth; blocked injections are still audited responses
    return {
        "answer": result["answer"],
        "blocked": result["blocked"],
        "injection": result["injection"],
        "usage": (result["completion"] or {}).get("input_tokens"),
        "provider": (result["completion"] or {}).get("provider"),
        "routing": result.get("routing"),
        "audit_seq": result.get("audit_seq"),
    }


@app.post("/v1/rag/ingest")
async def rag_ingest(
    body: IngestRequest,
    tenant: Tenant = Depends(get_tenant),
) -> dict:
    if "rag" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'rag' required")
    metrics.inc("aegis_rag_ingests_total", tenant=tenant.id)
    return rag_service.ingest(body.text, body.source)


@app.post("/v1/rag/query")
async def rag_query(
    body: RagQueryRequest,
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
        )
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc),
                            headers={"Retry-After": str(exc.retry_after)}) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    citations = ctx.citations if not result["injection"]["blocked"] else []
    return {
        "answer": result["answer"],
        "blocked": result["blocked"],
        "citations": citations,
        "routing": result.get("routing"),
        "audit_seq": result.get("audit_seq"),
    }


@app.post("/v1/chat/stream")
async def chat_stream(
    body: ChatRequest,
    tenant: Tenant = Depends(get_tenant),
    gateway: Gateway = Depends(get_gateway),
):
    if "chat" not in tenant.scopes:
        raise HTTPException(status_code=403, detail="scope 'chat' required")

    # Pre-checks share the same pipeline (no duplicate code path)
    try:
        result = await gateway.handle_chat(
            tenant_id=tenant.id,
            messages=[m.model_dump() for m in body.messages],
            max_tokens=body.max_tokens,
            use_cache=body.use_cache,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc),
                            headers={"Retry-After": str(exc.retry_after)}) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    async def event_gen():
        if result["blocked"]:
            payload = json.dumps(
                {"blocked": True, "injection": result["injection"], "answer": result["answer"]}
            )
            yield f"data: {payload}\n\n"
            yield "data: [DONE]\n\n"
            return
        # stream answer word-by-word (echo is instant; this shows real SSE plumbing;
        # GMI real streaming would proxy provider chunks here)
        text = result["answer"]
        words = text.split(" ")
        for i, w in enumerate(words):
            chunk = w + (" " if i < len(words) - 1 else "")
            yield f"data: {json.dumps({'delta': chunk, 'index': i})}\n\n"
            await asyncio.sleep(0.02)
        done_payload = json.dumps(
            {
                "done": True,
                "provider": (result["completion"] or {}).get("provider"),
                "routing": result.get("routing"),
                "audit_seq": result.get("audit_seq"),
                "injection": result["injection"],
            }
        )
        yield f"data: {done_payload}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/metrics")
async def prometheus_metrics():
    from fastapi import Response

    return Response(content=metrics.render(), media_type="text/plain; version=0.0.4")


@app.get("/admin/status")
async def admin_status(
    tenant: Tenant = Depends(get_tenant), gateway: Gateway = Depends(get_gateway)
) -> dict:
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


@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    html_path = Path(__file__).parent.parent / "templates" / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard not found</h1><p>Expected at templates/dashboard.html</p>", status_code=500)
