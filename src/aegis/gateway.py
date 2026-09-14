"""The Gateway orchestrator: the single pipeline every request passes through.

  auth -> rate limit -> injection scan (fail-closed) -> PII redact ->
  budget preflight -> cache -> route -> provider failover -> restore PII ->
  budget actuals -> audit chain append

`handle_chat` is transport-independent: FastAPI routes, eval runner and the
red-team harness all drive the same code path — one pipeline, no drift."""

import logging
import time
from typing import Any, AsyncIterator

from aegis.breaker import BreakerOpen
from aegis.budget import TokenBudget
from aegis.cache import TTLCache
from aegis.config import Settings
from aegis.context import request_id_ctx
from aegis.metrics import metrics
from aegis.providers.registry import AllProvidersDown, build_registry, complete_with_failover
from aegis.ratelimit import RateLimitExceeded, SlidingWindowLimiter
from aegis.router import estimate_cost_usd
from aegis.router import route as route_request
from aegis.security.audit import AuditChain
from aegis.security.auth import Authenticator
from aegis.security.injection import scan
from aegis.security.pii import build_vault

log = logging.getLogger("aegis.gateway")


def _log_event(event: str, tenant: str, **fields: object) -> None:
    """Structured operational log: ids and counters only, never content or keys."""
    detail = " ".join(f"{k}={v}" for k, v in fields.items())
    log.info("event=%s tenant=%s rid=%s %s", event, tenant, request_id_ctx.get(), detail)


def _optional_redis(url: str):
    """Shared limiter+budget backend when configured; None -> memory fallback.

    Import is lazy so `redis` stays out of minimal installs.
    Any failure returns None: callers degrade locally, never 500s.
    """
    if not url:
        return None
    try:
        import redis  # type: ignore[import-not-found]

        client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        client.ping()
        return client
    except Exception:  # noqa: BLE001 — any redis failure degrades to memory
        return None


class Gateway:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.auth = Authenticator(settings)
        shared_redis = _optional_redis(settings.redis_url)
        self.limiter = SlidingWindowLimiter(
            settings.rate_limit_per_min, redis_client=shared_redis
        )
        self.budget = TokenBudget(settings.daily_token_budget, redis_client=shared_redis)
        self.cache = TTLCache(settings.cache_ttl_seconds)
        self.audit = AuditChain(
            settings.audit_hmac_key,
            path=settings.audit_path,
            max_bytes=settings.audit_max_bytes,
            encrypt_key=settings.audit_encrypt_key,
            s3_bucket=settings.audit_s3_bucket,
            s3_prefix=settings.audit_s3_prefix,
        )
        self._vault_key = settings.vault_hmac_key
        self._vaults: dict[str, Any] = {}
        self.registry = build_registry(settings)

    def _vault_for(self, tenant: str):
        # per-tenant vault isolation: same HMAC key, separate maps.
        # prevents tenant A tokens restoring in tenant B responses.
        if tenant not in self._vaults:
            self._vaults[tenant] = build_vault(self._vault_key)
        return self._vaults[tenant]

    def _allowed_models(self, tenant: str) -> set[str] | None:
        allow = self.settings.model_allowlist().get(tenant)
        return allow or None

    @property
    def vault(self):
        # backward-compat for tests probing gw.vault
        return self._vault_for("default")

    async def handle_chat(
        self,
        tenant_id: str,
        messages: list[dict],
        max_tokens: int = 400,
        use_cache: bool = True,
    ) -> dict:
        tenant = tenant_id
        user_text = next((str(m["content"]) for m in reversed(messages)
                          if m.get("role") == "user"), "")

        # 1. rate limit
        rl = self.limiter.check(f"{tenant}:chat")
        if not rl.allowed:
            metrics.inc("aegis_rate_limited_total", tenant=tenant)
            raise RateLimitExceeded(rl.retry_after)
        quota = {"limit": self.settings.rate_limit_per_min, "remaining": rl.remaining}

        # 2. injection scan — three-band policy (fail closed at the top band):
        #    score >= block_threshold -> hard block, provider never called
        #    score >= soft_threshold  -> soft refusal, provider shielded from input
        #    below                    -> allow, logged for monitoring
        report = scan(user_text)
        if report.score >= self.settings.injection_block_threshold:
            report.blocked = True
            self.audit.append(tenant, "injection_blocked",
                              {"score": report.score, "labels": report.labels, "band": "hard"})
            metrics.inc("aegis_injection_blocked_total", tenant=tenant)
            _log_event("injection_blocked", tenant, score=report.score,
                       band="hard", labels=",".join(report.labels))
            return {
                "blocked": True,
                "injection": report.__dict__,
                "answer": ("Request blocked by AEGIS: potential prompt injection detected. "
                           "This incident has been logged."),
                "completion": None,
                "citations": [],
                "pii_masked": [],
                "rate_limit": quota,
            }
        if report.score >= self.settings.injection_soft_threshold:
            report.blocked = True
            report.notes = [*report.notes, "soft_refusal_provider_shielded"]
            self.audit.append(tenant, "injection_flagged",
                              {"score": report.score, "labels": report.labels, "band": "soft"})
            metrics.inc("aegis_injection_softblocked_total", tenant=tenant)
            _log_event("injection_flagged", tenant, score=report.score,
                       band="soft", labels=",".join(report.labels))
            return {
                "blocked": True,
                "injection": report.__dict__,
                "answer": ("I can't comply with instructions that attempt to override or "
                           "extract system behavior. Please rephrase your request."),
                "completion": None,
                "citations": [],
                "pii_masked": [],
                "rate_limit": quota,
            }

        # 3. PII redaction before anything leaves the trust boundary
        vault = self._vault_for(tenant)
        sanitized_user = vault.redact(user_text)
        pii_types = list(vault.masked_types)
        safe_messages = [
            {**m, "content": sanitized_user} if m.get("role") == "user" else m for m in messages
        ]

        # 4. budget preflight
        est_in = sum(self.budget.estimate_tokens(str(m.get("content", ""))) for m in messages)
        self.budget.preflight(tenant, est_in + max_tokens)

        # 5. cache (tenant-scoped key)
        tier, reason = route_request(safe_messages, self._allowed_models(tenant))
        cache_key = TTLCache.make_key(tenant, tier.model, safe_messages)
        cached = self.cache.get(cache_key) if use_cache else None

        if cached is not None:
            metrics.inc("aegis_cache_hits_total")
            completion = cached
            provider_name = completion.provider
        else:
            try:
                completion, provider_name = await complete_with_failover(
                    self.registry, safe_messages, tier.model, max_tokens,
                    preferred=None,
                )
            except AllProvidersDown:
                metrics.inc("aegis_provider_failures_total")
                _log_event("providers_down", tenant, providers=len(self.registry))
                raise
            self.cache.put(cache_key, completion)

        # 6. restore PII only for the authorized caller's view
        answer = vault.restore(completion.text)

        # 7. actuals + audit
        self.budget.record(tenant, completion.input_tokens + completion.output_tokens)
        record = self.audit.append(tenant, "chat_completed", {
            "model": completion.model,
            "provider": provider_name,
            "in_tokens": completion.input_tokens,
            "out_tokens": completion.output_tokens,
            "latency_ms": completion.latency_ms,
        })
        metrics.inc("aegis_requests_total", tenant=tenant, provider=provider_name)
        metrics.inc("aegis_tokens_total",
                    tenant=tenant,
                    direction="input",
                    value=float(completion.input_tokens))
        metrics.inc("aegis_tokens_total",
                    tenant=tenant,
                    direction="output",
                    value=float(completion.output_tokens))
        metrics.inc("aegis_cost_usd_total",
                    tenant=tenant,
                    provider=provider_name,
                    tier=tier.name,
                    value=estimate_cost_usd(tier, completion.input_tokens,
                                            completion.output_tokens))

        return {
            "blocked": False,
            "injection": report.__dict__,
            "answer": answer,
            "completion": {
                "text": completion.text,
                "model": completion.model,
                "provider": provider_name,
                "input_tokens": completion.input_tokens,
                "output_tokens": completion.output_tokens,
                "latency_ms": completion.latency_ms,
            },
            "routing": {"tier": tier.name, "reason": reason},
            "audit_seq": record.seq,
            "citations": [],
            "pii_masked": pii_types,
            "rate_limit": quota,
        }

    async def stream_chat(
        self,
        tenant_id: str,
        messages: list[dict],
        max_tokens: int = 400,
        use_cache: bool = True,
    ) -> AsyncIterator[dict]:
        """True streaming path with per-chunk output scan + TTFT.

        Yields `{"type": "delta", "delta": str}` chunks (PII-restored),
        then a terminal `{"type": "done", ...}` or `{"type": "blocked", ...}`.
        Chunks are word-boundary so vault tokens (`«hex»`, no spaces) never split.
        """
        import asyncio

        tenant = tenant_id
        t0 = time.perf_counter()
        user_text = next((str(m["content"]) for m in reversed(messages)
                          if m.get("role") == "user"), "")

        rl = self.limiter.check(f"{tenant}:chat")
        if not rl.allowed:
            metrics.inc("aegis_rate_limited_total", tenant=tenant)
            raise RateLimitExceeded(rl.retry_after)
        quota = {"limit": self.settings.rate_limit_per_min, "remaining": rl.remaining}

        report = scan(user_text)
        if report.score >= self.settings.injection_block_threshold:
            report.blocked = True
            self.audit.append(tenant, "injection_blocked",
                              {"score": report.score, "labels": report.labels,
                               "band": "hard", "stream": True})
            metrics.inc("aegis_injection_blocked_total", tenant=tenant)
            yield {"type": "blocked", "answer": ("Request blocked by AEGIS: potential "
                   "prompt injection detected. This incident has been logged."),
                   "injection": report.__dict__, "pii_masked": [], "rate_limit": quota}
            return
        if report.score >= self.settings.injection_soft_threshold:
            report.blocked = True
            report.notes = [*report.notes, "soft_refusal_provider_shielded"]
            self.audit.append(tenant, "injection_flagged",
                              {"score": report.score, "labels": report.labels,
                               "band": "soft", "stream": True})
            metrics.inc("aegis_injection_softblocked_total", tenant=tenant)
            yield {"type": "blocked", "answer": ("I can't comply with instructions that "
                   "attempt to override or extract system behavior. Please rephrase."),
                   "injection": report.__dict__, "pii_masked": [], "rate_limit": quota}
            return

        vault = self._vault_for(tenant)
        sanitized_user = vault.redact(user_text)
        pii_types = list(vault.masked_types)
        safe_messages = [
            {**m, "content": sanitized_user} if m.get("role") == "user" else m for m in messages
        ]

        est_in = sum(self.budget.estimate_tokens(str(m.get("content", ""))) for m in messages)
        self.budget.preflight(tenant, est_in + max_tokens)

        tier, reason = route_request(safe_messages, self._allowed_models(tenant))
        cache_key = TTLCache.make_key(tenant, tier.model, safe_messages)
        cached = self.cache.get(cache_key) if use_cache else None
        if cached is not None:
            metrics.inc("aegis_cache_hits_total")
            metrics.inc("aegis_stream_streams_total", tenant=tenant)
            answer = vault.restore(cached.text)
            first = True
            ttft_ms = 0.0
            words = answer.split(" ")
            for i, w in enumerate(words):
                delta = w + (" " if i < len(words) - 1 else "")
                if first:
                    ttft_ms = (time.perf_counter() - t0) * 1000
                    first = False
                metrics.inc("aegis_stream_chunks_total", tenant=tenant)
                yield {"type": "delta", "delta": delta, "index": i}
                await asyncio.sleep(0)
            self.budget.record(tenant, cached.input_tokens + cached.output_tokens)
            record = self.audit.append(tenant, "chat_completed", {
                "model": cached.model, "provider": cached.provider,
                "in_tokens": cached.input_tokens, "out_tokens": cached.output_tokens,
                "latency_ms": cached.latency_ms, "stream": True, "cached": True,
                "ttft_ms": round(ttft_ms, 2)})
            metrics.inc("aegis_ttft_ms_total", tenant=tenant, value=ttft_ms)
            yield {"type": "done", "provider": cached.provider,
                   "routing": {"tier": tier.name, "reason": reason},
                   "audit_seq": record.seq, "injection": report.__dict__,
                   "pii_masked": pii_types, "rate_limit": quota,
                   "ttft_ms": round(ttft_ms, 2), "cached": True}
            return

        # live stream across failover chain
        names = list(self.registry.keys())
        for name in names:
            provider, breaker = self.registry[name]
            if name != "echo" and not getattr(provider, "available", True):
                continue
            try:
                breaker.before_call()
            except BreakerOpen:
                continue
            try:
                sanitized_accum = ""
                restored_accum = ""
                chunks = 0
                ttft_ms = 0.0
                first = True
                provider_model = tier.model
                async for delta in provider.astream(safe_messages, tier.model, max_tokens):
                    if first:
                        ttft_ms = (time.perf_counter() - t0) * 1000
                        first = False
                        metrics.inc("aegis_ttft_ms_total", tenant=tenant, value=ttft_ms)
                    sanitized_accum += delta
                    # per-chunk output scan over trailing window (catches split smuggling)
                    tail = sanitized_accum[-2000:]
                    oreport = scan(tail)
                    if oreport.score >= self.settings.injection_block_threshold:
                        breaker.record_failure()
                        self.audit.append(tenant, "stream_blocked",
                                          {"score": oreport.score, "labels": oreport.labels,
                                           "chunks": chunks, "provider": name})
                        metrics.inc("aegis_injection_blocked_total", tenant=tenant)
                        yield {"type": "blocked",
                               "answer": ("Stream stopped by AEGIS: unsafe content "
                                          "detected mid-response. Incident logged."),
                               "injection": oreport.__dict__, "pii_masked": pii_types,
                               "rate_limit": quota}
                        return
                    restored = vault.restore(delta)
                    restored_accum += restored
                    chunks += 1
                    metrics.inc("aegis_stream_chunks_total", tenant=tenant)
                    yield {"type": "delta", "delta": restored, "index": chunks - 1,
                           **({"ttft_ms": round(ttft_ms, 2)} if chunks == 1 else {})}
                # stream finished for this provider
                breaker.record_success()
                from aegis.providers.base import Completion as _Completion
                in_tok = sum(len(str(m.get("content", ""))) // 4 + 1 for m in safe_messages)
                out_tok = len(sanitized_accum) // 4 + 1
                self.cache.put(cache_key, _Completion(
                    text=sanitized_accum, model=provider_model, provider=name,
                    input_tokens=in_tok, output_tokens=out_tok,
                    latency_ms=round((time.perf_counter() - t0) * 1000, 2)))
                self.budget.record(tenant, in_tok + out_tok)
                record = self.audit.append(tenant, "chat_completed", {
                    "model": provider_model, "provider": name,
                    "in_tokens": in_tok, "out_tokens": out_tok,
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                    "stream": True, "chunks": chunks, "ttft_ms": round(ttft_ms, 2)})
                metrics.inc("aegis_requests_total", tenant=tenant, provider=name)
                metrics.inc("aegis_stream_streams_total", tenant=tenant)
                metrics.inc("aegis_cost_usd_total", tenant=tenant, provider=name,
                            tier=tier.name,
                            value=estimate_cost_usd(tier, in_tok, out_tok))
                yield {"type": "done", "provider": name,
                       "routing": {"tier": tier.name, "reason": reason},
                       "audit_seq": record.seq, "injection": report.__dict__,
                       "pii_masked": pii_types, "rate_limit": quota,
                       "ttft_ms": round(ttft_ms, 2), "chunks": chunks}
                return
            except Exception as exc:  # noqa: BLE001 — try next provider in chain
                try:
                    breaker.record_failure()
                except Exception:  # noqa: BLE001,S110 — breaker bookkeeping never blocks failover
                    pass
                _log_event("stream_provider_failed", tenant, provider=name, err=str(exc)[:80])
                continue
        metrics.inc("aegis_provider_failures_total")
        raise AllProvidersDown("all providers failed during stream")

    async def aclose(self) -> None:
        return None


async def build_gateway(settings: Settings) -> Gateway:
    """Async factory; validates production secrets fail-closed."""
    problems = settings.require_production_secrets()
    if problems and settings.env == "production":
        raise RuntimeError("refusing to start in production: " + "; ".join(problems))
    gw = Gateway(settings)
    # warm-up: verify audit chain integrity at boot (tamper check)
    ok, msg = gw.audit.verify()
    if not ok:
        raise RuntimeError(f"audit chain failed verification at startup: {msg}")
    return gw
