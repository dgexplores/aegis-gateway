# STATUS — where this project stands

_Last updated: 2026-09-28. This is the handover document: what was done, what is
verified, what is still open, and how to deploy._

---

## 1. In one paragraph

AEGIS Gateway was reviewed as a senior engineer would review it, the critical
findings were fixed with a regression test each, and the system's capabilities
were then made **visible** — an interactive console, an audit read API, a document
lifecycle, and a reproducible evidence page. The suite grew from **121 → 493
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
- **Two surfaces.** `/dashboard` is the user surface and it is a *chat* surface:
  one question box, and a read-only list of what the assistant can see. No
  document-input form, no per-row delete, and not even a tab bar — the "Ask
  surface" was never a tab, so the one-item tablist underneath it was decoration
  that misreported the page's structure. Loading a corpus is corpus
  *administration* and belongs to an operator, not to the person asking about
  their holiday. `/admin` is the fleet surface, six tabs: Overview (counter
  window stated, because the counters are in-process and per-pod), Tenants,
  Chain, Attacks, **Controls**, and the Capability tour. Both load the same
  `dashboard.js`, so no renderer is forked.
- **Operator controls, from the portal.** `POST /admin/controls/*` — kill switch
  (refuse everyone), pause/resume a tenant, waive/revoke a tenant's *soft* band,
  and hold a provider's circuit open or closed. No shell, no `kubectl`, no
  `redis-cli`. Three properties worth naming:
  - The **soft-band waiver cannot waive the hard band.** There is no endpoint
    that could, and `test_operator_controls.py` asserts a hard injection is still
    blocked with the provider never called *while the tenant is allowlisted*. An
    allowlist that could switch off injection detection would be a hole in the
    one guarantee this product makes.
  - Decisions live in **Redis**, so they reach every replica and survive a
    restart. Without it they degrade to per-process state and the tab says
    **this pod only** rather than implying otherwise.
  - Pausing a tenant that does not exist returns **404**, so a typo cannot look
    like a successful containment. Every action is audited with the operator's
    id on it.
  - The **kill switch has its own second factor** (`AEGIS_BREAKGLASS_PASSWORD`),
    separate from the admin password so a compromised portal is not the same as
    the ability to halt every tenant. Restoring traffic is never gated — an
    incident must not end with a gateway nobody can switch back on. The secret
    is rate limited per actor, and both the successful use and the refused
    attempt are audited, because a stranger reaching for this from a hijacked
    session should not read like the operator who was asked to. Unset warns
    rather than blocks, and the admin UI says in as many words that the control
    is unguarded; shipping the demo secret fails the production guard.
- **Admin portal login** — an id and a password answering with a signed, HttpOnly,
  SameSite=Strict session cookie, so an operator mid-incident is not pasting a
  scoped key into a form, and an XSS on the page does not hand over the session.
  The same routes still accept an `admin`-scoped bearer token, so turning the
  login on cannot break an existing scraper. A failed login is **not** audited:
  it is not evidence, and logging the guess would turn the chain into an oracle
  for hunting valid ids. Shipping the published demo pair **fails the production
  guard** in both deploy artifacts.
- **Measured, not assumed: load and key hygiene.** `make loadtest` boots a
  gateway with the `echo` provider and reports percentiles. Single-process
  ceiling **~1,400 rps** at concurrency 50 (p50 26 ms, p99 122 ms), and it is
  the GIL rather than one hot spot: the audit `fsync` is 0.019 ms of a ~0.7 ms
  request and HMAC 0.73 µs. `authenticate()` is O(tenants) per request by
  design (timing-safe scan) and measured flat from 1 to 100 tenants. None of it
  includes provider latency — a real model took 3–8 s, so gateway overhead is
  noise and concurrency, not rps, is the axis that matters.
- **One key can no longer identify two tenants.** `Authenticator` keyed its
  lookup by key hash, so two tenants sharing a hash meant the second `dict`
  assignment silently overwrote the first: one tenant vanished and its callers
  were served as the other, with its scopes. Replayed against the old code, a
  shared key resolved to `globex` with `chat+rag+admin` while `acme` disappeared
  — cross-tenant privilege escalation with no error anywhere. Now refused at
  construction in **every** environment (a cross-tenant hole should not be gated
  on a deployment mode) and reported by the production boot check.
- **`hidden` actually hides.** A pre-existing CSS bug: the browser's
  `[hidden] { display: none }` is a UA-stylesheet rule, so *any* author rule
  setting `display` beat it. Only `.view[hidden]` was handled, so the admin key
  editor sat on screen while `el.hidden` reported `true` — the DOM and the
  screen disagreed, and nothing could see it. Fixed with one global
  `[hidden] { display: none !important }` plus a test.
- **Attacks view** — every hard block and soft refusal, read from the chain. The
  band comes from the *signed event name*, so it holds on a chain written without
  payload copies; score and labels need `AEGIS_AUDIT_ENCRYPT_KEY` and render as
  "not retained" when it is absent. No "add to blocklist" action, on purpose.
  Self-contained on both surfaces: no CDN, no web fonts, no framework, zero
  inline script/style.
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
PYTEST      466 passed, 5 live skipped
VERIFY OK — lint+type+tests+redteam+evals+rag+pii+prod-guard green
```

`ruff check` clean · `mypy src` clean (33 files) · live smoke suite 12/12 checks
pass (a 13th admin probe is skipped without an admin-scoped key) ·
`make evidence` reproduces the evidence page.

---

## 3a. Cleared since the last status

- **Deploy secrets fail closed.** `docker-compose.yml` requires the admin
  username, password, session key and break-glass secret via `:?`, so a boot
  without them stops instead of silently falling back to bearer-only auth.
  `prod_guard.py` also fails the build if any shipped artifact carries a
  `REPLACE_ME` / `change-me` value in those fields — a placeholder password is a
  *published* password, which is worse than a missing one. The k8s Secret ships
  the keys absent with commented guidance rather than as placeholders.
- **Restore drill.** `make restore-drill` (`scripts/restore_drill.py`) copies an
  archived chain to its operational path and reads it back through the same
  `verify()` / `tail_records()` an `/admin/audit` request uses. 12 tests attack it
  with a forged event, tenant and timestamp, a removed record, a reordering and a
  mismatched HMAC key, and require each to fail. It states the two things it
  cannot cover — tail loss, which needs an `--expect-head` anchor, and payload
  contents, which are not stored at all without `AEGIS_AUDIT_ENCRYPT_KEY`.
- RTO/RPO are written down in the README as a table, including the two rows that
  read *none*: the RAG corpus and the Redis counters have no recovery story yet.

## 4. What is left

The full path from here to a defensible production claim — ordered, gated, and
with the items that are blocked on something other than work marked as such — is
in [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md).

### 4.1 Eval corpus depth — partly landed, still the top item

**M1 / M2 / M3.** The three CI gates were plumbing assertions. The first pass at
this landed in `412a880`. Measured today by running the gates themselves:

| Gate | Was | Now | Roadmap target |
|---|---|---|---|
| PII | 1–2 cases per type | **207 cases, ≥20 per type, 9 types**, P=1.00 R=1.00 on every type | ≥20 per type — **met** |
| Retrieval | tiny corpus, gate could not fail | **52 documents, 58 grounded queries**, recall@4 100% on all three arms, drift baseline in place | ≥50 documents — **met**; ≥200 queries — **not met** |
| Benign FP | no harness | **200 cases, 0 false positives**, blocking at score ≥ 0.7; 67% of cases trip at least one pattern and 35 sit at ≥0.45 | ≥200 prompts — **met** |
| Injection | 12 vectors | 12 vectors, no band taxonomy | ≥40 across 3 bands — **not met** |

`recall@4 = 100%` and `0.00%` FP are now real measurements rather than
tautologies — the benign tail reaches 0.65 against a 0.70 block line, so the
weight table is genuinely under test. Two caveats keep this honest: the corpora
are hand-authored, not sampled from production traffic, and M3's other half is
still open — the groundedness judge runs against the `echo` stub, so no number
here is a real-model number yet.

Remaining slice, still **data, not code**: 200 grounded queries, and 40 banded
injection vectors (encoded, multi-turn, role-tag smuggling).

### 4.2 Scheduled hardening

| ID | Issue | Consequence |
|---|---|---|
| **M6** | `audit.append` fsyncs on the event loop; embedding providers use synchronous `httpx.post` inside async handlers | Throughput ceiling under concurrency. Partly mitigated (`asyncio.to_thread` on the audit path) but the embeddings call is still blocking |
| **H7** | `/metrics` is readable by any tenant and the series carry per-tenant labels | Cross-tenant disclosure. Tightening to `admin` breaks existing scrape configs, so it needs a deliberate rollout |
| **M12** | *Partly closed.* Segments now assemble into one ledger with proven continuity, served on `/admin/audit`; each pod still writes its own chain and there is no sequence global across pods | A lost segment is now detected rather than looking like a second pod. Reconciling pods still needs a schedule and archived segments pulled back |
| **M13** | `/readyz` re-reads the whole audit file | Cost grows with chain length; a probe should not do full verification |
| **M10** | No stale-chunk policy for RAG | A re-ingested document's old chunks can linger |
| **M4** | Injection false positives are measured now, but only against a hand-authored corpus | 200 prompts, 0 false positives, worst case 0.65 against a 0.70 block line. Real traffic would be a stronger sample, and a benign prompt at 0.68 would still be refused |
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

## 4a. Runbook

[`docs/RUNBOOK.md`](docs/RUNBOOK.md) — the kill switch, a corrupt chain, a
provider outage, a suspected admin compromise, and the audit key rotation, each
with what makes it worse. It ends with the things it *cannot* help with yet, so
nobody spends an incident reading it.

## 5. How to run it

```bash
git clone git@github.com:dgexplores/aegis-gateway.git && cd aegis-gateway
bash scripts/setup.sh                 # venv, deps, .env, verification
source .venv/bin/activate
make run                              # uvicorn on :8080
# then open http://localhost:8080/dashboard
```

```bash
make verify      # lint + types + 493 tests + red-team + evals + rag + pii + benign + prod-guard
make smoke       # live end-to-end against a running gateway (13 checks)
make evidence    # regenerate docs/capability-evidence.html from a real run
```

Deeper reading: `README.md` (product) · `docs/ARCHITECTURE.md` (ADRs, failure
modes, SLOs) · `CODE_REVIEW_AEGIS_GATEWAY.md` (findings + remediation log) ·
`docs/capability-evidence.html` (what the system does, from a live run).
