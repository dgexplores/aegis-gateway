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
- Sanitization is **role-agnostic**: `_scan_conversation` and
  `_redact_conversation` process every message in the request, not just `user`
  turns. Two reasons. The request schema accepts a client-supplied `system`
  role, so a role-filtered pipeline scored that payload 0.0 and forwarded it
  verbatim. And the RAG path passes retrieved document text as a `system`
  message, so a role-filtered pipeline sent document PII to the provider in the
  clear while still reporting `pii_masked: []`. Policy on whether a client may
  supply a `system` turn at all is separate and opt-in
  (`AEGIS_ALLOW_CLIENT_SYSTEM_PROMPT`, default true for drop-in clients).
- RAG: one `HybridRetriever` per tenant (`RagService._stores`). No cross-tenant
  retrieval. Source names returned un-namespaced; isolation is structural.
- Vault: one `Vault` per tenant, same HMAC key, separate maps. Tenant B can
  never restore tenant A tokens.
- Cache keys embed tenant id, model, messages and `max_tokens` (`max_tokens` is
  part of the key because answer length depends on it). Budgets, rate windows
  keyed `tenant:*`.
- Audit records embed tenant; verification is global (tamper-evidence),
  reads are filtered per tenant at API layer.
- Credentials: `Authenticator` refuses an empty bearer token outright, and
  `require_production_secrets` refuses to boot with no usable tenant or with a
  tenant whose key hash is `sha256("")` (which would let `Bearer ` with nothing
  after it authenticate) or the public demo hash.

## 5. State & reversibility (ADR summary)
- ADR-1 modular monolith, not microservices: one deployable, team of 1–5,
  boundaries are modules (security/rag/providers), reversible to services later.
- ADR-2 memory-first with Redis upgrade path: limiter accepts `redis_client`;
  `AEGIS_REDIS_URL` set -> shared sliding windows across replicas, unset ->
  in-process fallback so dev/tests run dependency-free (production refuses to
  boot without Redis — silent per-process limits would multiply × workers).
  Same pattern planned for cache/budget (keys already tenant-scoped, swap backend without API change).
- ADR-3 file audit with rotation-carry: JSONL `audit.jsonl`, each record HMACs
  `seq|ts|tenant|event|payload_sha256|prev_hash[|request_id]`. Rotation keeps
  head as first `prev_hash` of the new file; per-file `verify()` holds,
  cross-file continuity by matching head. Postgres/S3 sink later without
  changing record format. Multi-process safe: every append takes an `flock` +
  refreshes seq/head from the file tail, so `uvicorn --workers N` can't fork
  the chain. `request_id` is appended to the signed material **only when
  present**, so chains written before the field existed still verify
  byte-for-byte.
- ADR-5 audit read side (`tail_records`): a reverse **block reader** walks the
  file backwards in 64 KiB blocks, yielding at most `MAX_READ_RECORDS` (500)
  rows without scanning the whole file — read cost is O(rows returned), not
  O(file size). Every returned row is re-verified *on the way out*: `sig_ok`
  recomputes the HMAC, `link_ok` checks `prev_hash` against the predecessor's
  `entry_hash`, and `payload_ok` re-derives `sha256(decrypted bytes)` and
  compares it to the signed digest. One extra anchor row is read so the oldest
  *returned* row is still link-checkable; when the window does not reach the
  file start, the oldest row reports `link_ok: null` (unknown) rather than
  fabricating assurance. Reads never write, so reading cannot disturb the
  chain. Tenant-scoped by default; cross-tenant requires `admin`.
- ADR-6 document lifecycle: deleting a document is **durable-first**. The
  Postgres `DELETE` runs first and *raises* on failure (`RagPersistError` →
  `503`); the in-memory index is only mutated after the durable delete
  succeeds. The reverse order would report success, then be silently undone by
  `bootstrap()` replaying the still-present rows on the next restart. Index
  removal rebuilds BM25 `_doc_freq`/`_total_docs` from the surviving term
  frequencies instead of decrementing them — a decrement drifts and a deleted
  document keeps skewing rankings forever.
- ADR-4 echo fallback always last: guarantees liveness (never 503 on valid
  input when fallback exists), keeps evals/red-team deterministic.
- ADR-7 multi-pod ledger reconciliation (M12): each pod keeps its own chain
  (no single writer to become a single point of failure). Rotation uploads
  the sealed segment to `AEGIS_AUDIT_S3_BUCKET`. To reconcile: collect every
  segment (S3 objects + live tails via `/admin/audit/export`), verify each
  with `verify()`, then order segments by head linkage (segment B's first
  `prev_hash` equals segment A's last `entry_hash`). Segments that share no
  head link belong to different pods — that is expected, not corruption.
  Within one pod the order is total; across pods it is partial (merge by `ts`
  for a timeline view, never for verification).

## 6. Failure modes
| Failure | Behavior |
|---|---|
| Bad secrets in prod | refuse boot (`require_production_secrets`) |
| No usable tenant, or a tenant key hash of `sha256("")` / the public demo hash (prod) | refuse boot — an empty bearer token must never authenticate |
| Redis missing/unreachable at boot (prod) | refuse boot (per-process fallback would multiply limits × workers) |
| Redis flap at runtime | degrade to local view for that call, metric gap, no 500 |
| Corrupt audit at boot | refuse boot (`verify()` in `build_gateway`) |
| Provider 402/5xx/timeout **or an unexpected response shape** | breaker counts, failover to next, echo last (any exception fails over, not just `ProviderError`) |
| All providers down | 503 `AllProvidersDown`, no fake answer |
| Budget exceeded | 402 preflight (estimate) + post-call actuals |
| Rate exceeded | 429 + `Retry-After` |
| Durable document delete fails | 503 `RagPersistError`, in-memory index left untouched (durable-first ordering — never report a delete the store did not commit) |
| Oversized request body | 422 (`content` ≤32k, ≤64 messages) |
| Unknown key / scope | 401 / 403, timing-safe compare over all hashes |
| Client-supplied `system` turn when disabled by policy | 400 |

## 7. Observability
- `GET /healthz` liveness (no auth), `GET /readyz` readiness (audit verify +
  registry non-empty, no auth so K8s probes stay simple).
- `GET /metrics` Prometheus text (requests/tokens/cost/blocks/cache/budget),
  auth required (any tenant) — series carry per-tenant labels.
- `GET /admin/status` (`admin` scope): chain intact + length, cache stats, breaker
  snapshots, budget usage for caller tenant.
- `GET /admin/audit`: the read side of the chain (ADR-5). Returns the verified
  window with per-row `sig_ok`/`link_ok`/`payload_ok`, the decrypted payload when
  an encrypt key is set, and window metadata (`window_reached_start`, `truncated`,
  `malformed`, `all_signatures_valid`, `all_links_valid`). Self-scoped; `admin`
  for cross-tenant. `GET /admin/audit/export` streams the same window as NDJSON
  (`admin` only) for an auditor's own tooling.
- Audit appends run through `asyncio.to_thread` so the `flock` + `fsync` on the
  hot path cannot stall the event loop under concurrency; the append itself stays
  synchronous and ordered.
- `x-request-id` + `x-latency-ms` on every response via middleware; the id is
  also a `contextvars` value, so gateway logs (`event= tenant= rid=`) correlate
  with access logs without touching PII or keys. It is signed into the audit
  record, so a log line can be tied to a specific chain entry.
- Retry policy = failover chain (try next provider, breaker tracks); timeout
  budget = 30s per provider call; idempotency = exact-match tenant cache
  (safe client retries); TLS terminates at ingress, DB role is CRUD-only on
  `rag_chunks`, audit evidence survives via rotation-carry + opt-in PVC
  (`deploy/k8s/pvc.yaml`) until the S3 archive lands.

## 8. Capability console (`/dashboard`) & the static surface
The console is a single unauthenticated HTML page plus two static assets; it is
the surface that makes the gateway's security properties *visible* rather than
merely true. It is deliberately dependency-free.

- **No CDN, no web fonts, no framework.** A gateway sold into regulated and
  air-gapped environments cannot assume the operator's browser has outbound
  internet. `dashboard.css` and `dashboard.js` ship from `/static`; the page
  carries zero inline `style=`/`<script>` and one `<script src="/static/...">`.
- **Strict CSP is a consequence of that choice.** `script-src 'self';
  style-src 'self'; font-src 'self'; form-action 'none'` — no `unsafe-inline`
  anywhere, no remote origins. Because the assets are same-origin files, the
  policy costs nothing to enforce.
- **The demo key is dev-only.** `/dashboard` is unauthenticated; the key field
  is pre-filled from `AEGIS_DEMO_API_KEY` *only* when `AEGIS_ENV != production`.
  The route substitutes the slot at render time, so the production page ships an
  empty field.
- **The tour grades the real API.** The ten capability checks issue real
  requests through the same routes clients use and compare what they observe to
  what the gateway claims. Nothing is simulated; a drift between the console and
  the API is a test failure (`test_console.py` asserts every fetched path exists
  in the route table).
- **The outbound preview is a diagnostic, not product surface.** The
  "what the model received" panel reflects `outbound` in the chat response,
  which the gateway populates only when `env != production`. It shows the
  sanitized payload with vault pseudonyms highlighted — useful for exactly the
  audience that needs to be convinced the redaction is real.

## 9. SLOs (single-region, 3 replicas)
- Availability 99.9%/mo excluding upstream provider outages (echo fallback
  keeps valid-input serving up; `/readyz` sheds not-ready pods).
- p95 `/v1/chat` < 500ms on echo/cache path, provider-bound otherwise
  (upstream latency excluded, tracked per provider in audit payloads).
- Correctness budget: eval gate >= 85%, red-team 0 leaks, retrieval drift 0 —
  any breach blocks the merge (error budget enforced in CI, not meetings).
- Alert on: breaker open > 5m, budget > 80% for any tenant, audit verify fail.

## 10. Phase-2/3 tracks
- Streaming: providers expose `astream` (GMI/OpenAI true SSE, echo word deltas);
  `Gateway.stream_chat` redacts once, scans each trailing 2k window per chunk,
  restores PII per word-chunk (vault tokens contain no spaces, never split),
  records TTFT (`aegis_ttft_ms_total`, done-event `ttft_ms`).
- Router: `AEGIS_TENANT_MODELS` allowlist enforced at route time (reason notes
  enforcement); `MODEL_PRICES_USD_PER_1K` gives per-call $ real rates.
- Audit: `payload_enc/payload_alg` copies (Fernet if installed, else base64
  envelope); rotation best-effort uploads to `AEGIS_AUDIT_S3_BUCKET`.
- RAG: `rag/embeddings.py` (`legacy|hash|gmi|openai`); legacy default keeps
  evals deterministic; `rag_chunks.embedding TEXT` persists vectors.
- Evals: `grow_golden.py` (dedup+validate prod misses) and eval-gate
  `--baseline/--max-drop/--write-baseline` delta gating.
- Fuzz: `fuzz_attacks.py` seeded mutations (multilingual, homoglyph,
  zero-width, b64, role-tag); evasions to `attacks_fuzz.yaml` for review.
