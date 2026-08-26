"""The Gateway orchestrator: the single pipeline every request passes through.

  auth -> rate limit -> injection scan (fail-closed) -> PII redact ->
  budget preflight -> cache -> route -> provider failover -> restore PII ->
  budget actuals -> audit chain append

`handle_chat` is transport-independent: FastAPI routes, eval runner and the
red-team harness all drive the same code path — one pipeline, no drift."""

from typing import Any

from aegis.budget import BudgetExceeded, TokenBudget
from aegis.cache import TTLCache
from aegis.config import Settings
from aegis.metrics import metrics
from aegis.providers.registry import AllProvidersDown, build_registry, complete_with_failover
from aegis.ratelimit import RateLimitExceeded, SlidingWindowLimiter
from aegis.router import route as route_request
from aegis.security.audit import AuditChain
from aegis.security.auth import Authenticator
from aegis.security.injection import scan
from aegis.security.pii import build_vault


class InjectionBlocked(Exception):
    def __init__(self, report: Any) -> None:
        self.report = report
        super().__init__("prompt injection blocked")


class Gateway:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.auth = Authenticator(settings)
        self.limiter = SlidingWindowLimiter(settings.rate_limit_per_min)
        self.budget = TokenBudget(settings.daily_token_budget)
        self.cache = TTLCache(settings.cache_ttl_seconds)
        self.audit = AuditChain(settings.audit_hmac_key)
        self.vault = build_vault(settings.vault_hmac_key)
        self.registry = build_registry(settings)

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
            return {
                "blocked": True,
                "injection": report.__dict__,
                "answer": ("Request blocked by AEGIS: potential prompt injection detected. "
                           "This incident has been logged."),
                "completion": None,
                "citations": [],
            }
        if report.score >= self.settings.injection_soft_threshold:
            report.blocked = True
            report.notes = [*report.notes, "soft_refusal_provider_shielded"]
            self.audit.append(tenant, "injection_flagged",
                              {"score": report.score, "labels": report.labels, "band": "soft"})
            metrics.inc("aegis_injection_softblocked_total", tenant=tenant)
            return {
                "blocked": True,
                "injection": report.__dict__,
                "answer": ("I can't comply with instructions that attempt to override or "
                           "extract system behavior. Please rephrase your request."),
                "completion": None,
                "citations": [],
            }

        # 3. PII redaction before anything leaves the trust boundary
        sanitized_user = self.vault.redact(user_text)
        safe_messages = [
            {**m, "content": sanitized_user} if m.get("role") == "user" else m for m in messages
        ]

        # 4. budget preflight
        est_in = sum(self.budget.estimate_tokens(str(m.get("content", ""))) for m in messages)
        self.budget.preflight(tenant, est_in + max_tokens)

        # 5. cache (tenant-scoped key)
        tier, reason = route_request(safe_messages, list(self.registry.keys()))
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
                raise
            except BudgetExceeded:
                raise
            self.cache.put(cache_key, completion)

        # 6. restore PII only for the authorized caller's view
        answer = self.vault.restore(completion.text)

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
        }

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
