# AEGIS Gateway — Systematic Plan

## Phase 0 — Done (main green)
- [x] Pipeline `handle_chat`, 3-band scan, per-tenant vault/RAG/cache keys
- [x] CI: lint+type, matrix tests+coverage, secrets scan, dep audit,
      redteam + eval gates, docker build+smoke
- [x] CD: GHCR SBOM/provenance, staging auto, prod tag gate + approval
- [x] K8s: RollingUpdate, probes, PDB, NetworkPolicy, kustomize
- [x] UI: simple-first dashboard (3 steps, onboarding, Advanced toggle)

## Phase 1 — Robust handling (this change)
Goal: replicas agree, disks don't fill, clients get precise errors.
- [x] `AEGIS_REDIS_URL`: set -> shared rate windows; unset -> memory fallback.
      Redis down -> degrade locally, never 500.
- [x] Audit rotation with head carry-over (`AEGIS_AUDIT_MAX_BYTES`,
      default 10 MB). Per-file verify holds; continuity via head match.
- [x] Precise errors: 401/403 auth, 429+Retry-After, 402 budget, 503 providers
      down, 500 generic (no leak) with `x-request-id`.
- [x] `/readyz` readiness (audit + registry) separate from `/healthz` liveness.
- [x] CI `integration` job: redis service + full `make verify` + smoke with
      `AEGIS_REDIS_URL` set. Manifest render check (`kustomize build` or
      yamlload fallback). CD preflight renders manifests before staging smoke.

## Phase 2 — Persistence (done)
- [x] Postgres source-of-truth for RAG (`store/db.py`, tenant PK, idempotent
      schema, boot rebuild, write-through best-effort, `verify_persistence.py`).
- [x] Budgets shared via Redis (`budget:{tenant}:{day}`), memory fallback.
- [x] Audit encrypted payload copy + S3 archive on rotation (`encrypt_key`,
      `audit_s3_bucket/prefix`, Fernet-when-installed else base64 envelope;
      JSONL format kept for export, old lines still verify).
- [x] Router: per-tenant model allowlist (`AEGIS_TENANT_MODELS`) + real $/1k
      table (`MODEL_PRICES_USD_PER_1K`); tier rules still pick the tier.
- [x] Embedding column + pluggable vectors (`rag/embeddings.py`: legacy default
      so evals stay deterministic; `hash|gmi|openai` opt-in, JSON column,
      retriever prefers real cosine with lexical fallback).

## Phase 3 — Quality moat
- [x] Retrieval eval (`rag_eval.py`): recall@k + MRR per arm (hybrid/bm25/vector),
      committed baseline = drift gate in CI.
- [x] Fairness seed: Hinglish paraphrase cases in golden set (same bar as English).
- [x] Golden set growth: `grow_golden.py` promotes prod misses (dedup +
      validate, `--dry-run`); eval gate supports `--baseline/--max-drop` delta
      gating plus `--write-baseline` (gate on delta, not absolute).
- [x] Attacker-agent fuzz (`fuzz_attacks.py`): seeded multilingual/paraphrase/
      homoglyph/base64/role-tag mutations over `attacks.yaml`; evasions go to
      `attacks_fuzz.yaml` for human review before promotion.
- [x] India PII pack (Aadhaar w/ Verhoeff, PAN, passport, UPI) + `pii_eval.py`
      precision/recall harness (in `make verify`).
- [x] True streaming: provider `astream` SSE (GMI/OpenAI real proxy, echo words),
      `Gateway.stream_chat` per-chunk output scan + TTFT metric, `/v1/chat/stream`
      serves it with quota headers.

## CI/CD design (how gates work)
```
PR: lint-type + test(3.11,3.12) + secrets + dep-audit
      -> gates (redteam 0-leak, eval >=85%) -> docker (build+smoke)
main push: ci again + cd (GHCR push, staging smoke, prod on tag v*)
```
- Concurrency cancel on PR refs; required checks = all ci jobs.
- Secrets: `STAGING_URL/KEY` only in env; image never contains `.env`.
- Rollback: re-tag previous `sha-*`, `kubectl rollout undo`.

## Robustness checklist (each PR)
- [ ] `make verify` green (lint, type, tests, redteam, evals)
- [ ] New state namespaced per tenant; no global maps without tenant key
- [ ] External dep (redis/db/provider) has timeout + fallback, never bare 500
- [ ] Errors carry status + request-id, never raw exceptions or keys
- [ ] Manifests still render; probes unchanged paths
