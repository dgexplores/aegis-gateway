# AEGIS Gateway — Architecture

## 1. What it is
One secure door for every AI call. Apps speak OpenAI-compatible HTTP to AEGIS;
AEGIS checks, scrubs, budgets, routes, logs, then calls a real provider
(GMI / OpenAI / Anthropic) with `echo` as deterministic last resort.

## 2. Context (C4 L1)
```
Apps/Bots/Agents --> AEGIS Gateway --> GMI Cloud / OpenAI / Anthropic / echo
                         |
                    audit log, /metrics, /admin/status, dashboard
```
Only the gateway holds HMAC keys and tenant hashes. Providers see sanitized
text only. Callers see restored PII only for their own tenant.

## 3. Request pipeline (single code path)
`Gateway.handle_chat` is transport-independent: FastAPI routes, eval runner,
red-team harness all drive it. No drift.
```
auth -> rate limit -> injection scan (3-band, fail-closed)
  -> PII redact (per-tenant vault) -> budget preflight
  -> cache (tenant-scoped key) -> route (economy/premium)
  -> provider failover + breaker -> restore PII (same tenant only)
  -> budget actuals -> audit append (HMAC chain)
```
Bands: `<0.35` allow · `0.35–0.7` soft-refuse, provider shielded · `>=0.7`
hard-block, provider never called. Scan errors fail CLOSED at API layer.

## 4. Data isolation (multi-tenant rules)
- RAG: one `HybridRetriever` per tenant (`RagService._stores`). No cross-tenant
  retrieval. Source names returned un-namespaced; isolation is structural.
- Vault: one `Vault` per tenant, same HMAC key, separate maps. Tenant B can
  never restore tenant A tokens.
- Cache keys embed tenant id. Budgets, rate windows keyed `tenant:*`.
- Audit records embed tenant; verification is global (tamper-evidence),
  reads are filtered per tenant at API layer.

## 5. State & reversibility (ADR summary)
- ADR-1 modular monolith, not microservices: one deployable, team of 1–5,
  boundaries are modules (security/rag/providers), reversible to services later.
- ADR-2 memory-first with Redis upgrade path: limiter accepts `redis_client`;
  `AEGIS_REDIS_URL` set -> shared sliding windows across replicas, unset ->
  in-process fallback so dev/tests run dependency-free. Same pattern planned
  for cache/budget (keys already tenant-scoped, swap backend without API change).
- ADR-3 file audit with rotation-carry: JSONL `audit.jsonl`, each record HMACs
  `seq|ts|tenant|event|payload_sha256|prev_hash`. Rotation keeps head as first
  `prev_hash` of the new file; per-file `verify()` holds, cross-file continuity
  by matching head. Postgres/S3 sink later without changing record format.
- ADR-4 echo fallback always last: guarantees liveness (never 503 on valid
  input when fallback exists), keeps evals/red-team deterministic.

## 6. Failure modes
| Failure | Behavior |
|---|---|
| Bad secrets in prod | refuse boot (`require_production_secrets`) |
| Corrupt audit at boot | refuse boot (`verify()` in `build_gateway`) |
| Provider 402/5xx/timeout | breaker counts, failover to next, echo last |
| All providers down | 503 `AllProvidersDown`, no fake answer |
| Redis down | degrade to local limiter view, metric gap, no 500 |
| Budget exceeded | 402 preflight (estimate) + post-call actuals |
| Rate exceeded | 429 + `Retry-After` |
| Unknown key / scope | 401 / 403, timing-safe compare over all hashes |

## 7. Observability
- `GET /healthz` liveness (no auth), `GET /readyz` readiness (audit verify +
  registry non-empty, no auth so K8s probes stay simple).
- `GET /metrics` Prometheus text (requests/tokens/blocks/cache/budget).
- `GET /admin/status` (auth): chain intact + length, cache stats, breaker
  snapshots, budget usage for caller tenant.
- `x-request-id` + `x-latency-ms` on every response via middleware.
