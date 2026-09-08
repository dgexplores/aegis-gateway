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

## Phase 2 — Persistence (in progress)
- [x] Postgres source-of-truth for RAG (`store/db.py`, tenant PK, idempotent
      schema, boot rebuild, write-through best-effort, `verify_persistence.py`).
- [x] Budgets shared via Redis (`budget:{tenant}:{day}`), memory fallback.
- [ ] Audit encrypted payload column + S3 archive; keep JSONL format for export.
- [ ] Router: per-tenant model allowlist + real $/1k (tier rules only for now).
- [ ] Embedding column + real vector index (needs embedding provider decision).

## Phase 3 — Quality moat
- Golden set 10 -> 100 (prod-sampled misses), LLM judge + heuristic, gate on
  delta not absolute.
- Attacker-agent fuzz -> auto-grow `attacks.yaml` (multilingual, paraphrase).
- India PII pack (Aadhaar/PAN/passport/UPI) + precision/recall harness.
- True SSE proxy with per-chunk scan + TTFT metric.

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
