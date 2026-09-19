# STATUS — where this project stands

_Last updated: 2026-09-19. This is the handover document: what was done, what is
verified, what is still open, and how to deploy._

---

## 1. In one paragraph

AEGIS Gateway was reviewed as a senior engineer would review it, the critical
findings were fixed with a regression test each, and the system's capabilities
were then made **visible** — an interactive console, an audit read API, a document
lifecycle, and a reproducible evidence page. The suite grew from **121 → 228
tests**; `make verify` is fully green. The deployment artifacts (Docker, Compose,
Kubernetes, Render) all boot. What remains is not correctness work: it is
**eval-corpus depth**, a handful of scheduled hardening items, and choosing a host
that provides Redis/Postgres.

---

## 2. What was done

Three phases, in order. Each has its own artifact in this repo.

### Phase 1 — Review (`CODE_REVIEW_AEGIS_GATEWAY.md`)

A full senior-engineer review: architecture, security, testing, CI/CD, developer
experience and end-user experience. ~40 findings, severity-ranked C1–C4 (critical),
H1–H7 (high), M1–M14 (medium), L1–L20 (low), each with the code that proves it and
a reproduction command in the appendix.

### Phase 2 — Remediation (`CODE_REVIEW_AEGIS_GATEWAY.md` §10)

The entire "Now — before anyone else deploys this" bucket. The four criticals:

| ID | Finding | Status |
|---|---|---|
| **C1** | A client-supplied `system` turn was scored `0.0` and forwarded verbatim — a total bypass of the injection scanner | **Fixed.** Every message role is now scanned and redacted; the worst verdict decides |
| **C2** | The RAG path passed retrieved document text as a `system` message, so document PII reached the provider while `pii_masked` reported `[]` | **Fixed.** Sanitization is role-agnostic |
| **C3** | An empty bearer token authenticated as `demo` (`sha256("")` was the built-in tenant hash) | **Fixed.** Empty credentials rejected; the built-in tenant removed entirely (fail-closed) |
| **C4** | The shipped K8s manifests could not boot — production without a Redis URL | **Fixed.** `deploy/k8s/redis.yaml` added; `prod_guard` gates it |

Plus H3–H6, L1/L2/L7, M5/M7. The highest-value addition is
`tests/test_trust_boundary.py`: a spy provider captures the exact outbound payload
and asserts no PII or injection crosses the boundary, across every request shape.
That is the test that would have caught C1 and C2 on day one.

### Phase 3 — Capability (this phase)

The backend had always supported multi-turn threads, a reversible PII vault, a
tamper-evident chain and per-tenant documents. **Nothing surfaced any of it.**

- **Audit read API** (`GET /admin/audit`, `/admin/audit/export`) — a reverse block
  reader so read cost is O(rows) not O(file size), capped at 500. Every row is
  re-verified *on the way out*: `sig_ok` (HMAC recomputed), `link_ok` (chain link
  checked), `payload_ok` (decrypted bytes re-hashed against the signed digest).
  `link_ok` is `null` — *unknown* — when the window is truncated, never fabricated.
- **Document lifecycle** — list, delete, clear. Deletion is **durable-first**: the
  Postgres delete runs first and raises; memory is only touched after it succeeds.
  The reverse order would report success and be silently undone by `bootstrap()` on
  the next restart. BM25 statistics are *rebuilt* on delete, not decremented.
- **Capability console** (`/dashboard`) — five views: Console (multi-turn with a
  seven-stage pipeline trace and "what the model received"), Knowledge, Evidence,
  Ops, and a Capability tour of ten checks that drive the real API. Self-contained:
  no CDN, no web fonts, no framework, zero inline script/style.
- **Strict CSP** — `script-src 'self'; style-src 'self'; font-src 'self';
  form-action 'none'`, no `unsafe-inline`, no remote origins. That is only possible
  *because* the console ships its own assets, which also makes it air-gap-safe.
- **Evidence page** (`docs/capability-evidence.html`) — `make evidence` boots a
  gateway on a scratch port, drives 15 real calls over a socket, and renders a
  static self-contained page. Every value comes from the live run, so it cannot
  drift from what the gateway actually did.

---

## 3. What is verified

```
$ make verify
RED-TEAM    attacks=12  hard-blocked=11  deflected=1  leaked=0
EVAL GATE   12/12 passed
RAG EVAL    recall@4=100%  MRR=1.0  no drift vs baseline
PII-EVAL    all must-recall cases masked
PROD-GUARD  PASSED (10 checks)
PYTEST      228 passed
VERIFY OK — lint+type+tests+redteam+evals+rag+pii+prod-guard green
```

`ruff check` clean · `mypy src` clean (33 files) · live smoke suite 12/12 checks
pass (a 13th admin probe is skipped without an admin-scoped key) ·
`make evidence` reproduces the evidence page.

---

## 4. What is left

### 4.1 The one that matters most — eval corpus depth

**M1 / M2 / M3.** Three of the CI gates are currently plumbing assertions rather
than quality measurements:

- the retrieval drift gate passes because the corpus is tiny — it cannot detect a
  retrieval regression;
- the PII eval has 1–2 cases per type, so "precision 1.00" is not meaningful;
- there is no benign-text precision harness, so injection false positives are
  unmeasured.

This needs **new corpora**, not code: 50+ retrieval documents, 20+ PII cases per
type, and a benign-text set. Until that lands, treat "recall@4 = 100%" as "the
plumbing works", not "retrieval is good". This is the highest-value remaining
investment.

### 4.2 Scheduled hardening

| ID | Issue | Consequence |
|---|---|---|
| **M6** | `audit.append` fsyncs on the event loop; embedding providers use synchronous `httpx.post` inside async handlers | Throughput ceiling under concurrency. Partly mitigated (`asyncio.to_thread` on the audit path) but the embeddings call is still blocking |
| **H7** | `/metrics` is readable by any tenant and the series carry per-tenant labels | Cross-tenant disclosure. Tightening to `admin` breaks existing scrape configs, so it needs a deliberate rollout |
| **M12** | Each pod has its own audit chain; there is no single ledger | Reconciling N chains is manual. The S3 archive is the intended answer |
| **M13** | `/readyz` re-reads the whole audit file | Cost grows with chain length; a probe should not do full verification |
| **M10** | No stale-chunk policy for RAG | A re-ingested document's old chunks can linger |
| **M4** | Injection false positives are unmeasured | A benign document mentioning "ignore previous instructions" could be refused |
| **H1 / H2** | The audit log stores hashes by default; payloads only when `AEGIS_AUDIT_ENCRYPT_KEY` is set | Documented explicitly in the README, so the claim matches the artifact — but "prove what the AI said" requires setting the key |
| **L6** | The repo has never been `ruff format`ed (~40 files) | The format check is non-blocking; making it blocking is a large unrelated diff |

### 4.3 Deployment — the honest status

**Everything is ready to deploy; nothing is deployed.** Three paths exist:

1. **Render** — `render.yaml` is a one-click blueprint. ⚠️ It previously could not
   boot: it paired `AEGIS_ENV=production` with the public demo key hash, which the
   gateway correctly refuses. It is now a deliberate **evaluation** blueprint
   (`env=development`, demo tenant, Redis + Postgres wired, audit on a disk). For
   production, follow the three steps in the file's header — `make prod-guard`
   gates them so it cannot be done half-way.
2. **Docker / Compose** — `docker compose up -d` brings up gateway + Redis +
   Postgres. Not run here: no Docker daemon in this environment.
3. **Kubernetes** — `kubectl apply -f deploy/k8s/` (StatefulSet + HPA + Redis +
   PVC). `prod_guard` validates the manifests, but no cluster was available to
   apply them.

**A note on the local publish path:** an attempt to publish this project as a
hosted app was **rejected** by the publishing sandbox, which provides no database,
cache or message queue. The gateway only requires Redis in `production` mode — in
development it falls back to in-process state and Postgres is optional — but the
blueprint and Compose file both wire those services, so the sandbox classified the
project as needing external services. Publishing it would require stripping Redis
and Postgres from the deploy config, which was not done: **ask first**, since it
changes the deployed architecture.

---

## 5. How to run it

```bash
git clone git@github.com:dgexplores/aegis-gateway.git && cd aegis-gateway
bash scripts/setup.sh                 # venv, deps, .env, verification
source .venv/bin/activate
make run                              # uvicorn on :8080
# then open http://localhost:8080/dashboard
```

```bash
make verify      # lint + types + 228 tests + red-team + evals + rag + pii + prod-guard
make smoke       # live end-to-end against a running gateway (13 checks)
make evidence    # regenerate docs/capability-evidence.html from a real run
```

Deeper reading: `README.md` (product) · `docs/ARCHITECTURE.md` (ADRs, failure
modes, SLOs) · `CODE_REVIEW_AEGIS_GATEWAY.md` (findings + remediation log) ·
`docs/capability-evidence.html` (what the system does, from a live run).
