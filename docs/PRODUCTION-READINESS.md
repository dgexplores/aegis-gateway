# Production readiness plan

What has to be true before AEGIS can honestly be called production grade, how we
will know, and what is blocked on something other than work.

`ROADMAP.md` covers where the product should go. `STATUS.md` records what is
true today. This file is the gap between the two.

**The rule, unchanged from the rest of the repo: a claim is only made if a gate
measures it.** Every item below names the gate that closes it. Anything without
a gate is an intention, and intentions are not progress.

---

## The honest headline

The single largest risk to this product is not a missing feature. It is that
**it has never been deployed anywhere real.**

Everything in Wave 1 is reasoning about behaviour that has only ever been
observed in-process, on a laptop, against a stub provider. Until a real
environment runs it for a sustained period, "production grade" is a prediction.
Not a wrong one — the design is sound and the gates are real — but a prediction.

So Wave 0 is not a formality. It is the gate that every later claim rests on.

---

## Wave 0 — Prove what already exists

Cheapest work in the plan, and it unblocks everything. No new code unless it
finds a bug.

| # | Item | Gate that closes it |
|---|---|---|
| 0.1 | Deploy to a real environment: Postgres, Redis, ≥2 replicas, a real model provider | `make prod-guard` passes **against the live config**, and `/readyz` reports ready for 7 consecutive days |
| 0.2 | Run against a real model, not `echo` — real prompts, real latency, real failures | `tests/test_live_provider.py` passes with **no skips**, and a p95 is measured on the real provider with the gateway's own overhead subtracted |
| 0.3 | Weekly restore from the live environment's backups | `make restore-drill --from <live backup>` passes from a **cold start**, unattended, on a schedule |
| 0.4 | Re-ingest the real corpus and re-run every gate against real traffic shapes | All gates green against production-shaped data, not the hand-authored corpora |

**Blocked on:** a cluster, a provider key with quota, and someone to own the
7-day window. Not blocked on code.

**Why 0.2 matters more than it looks.** The single worst bug found in this
project so far — a provider returning HTTP 200 with no content, which surfaced
as a `500` to the caller on an ordinary input — was invisible to every test,
because every other test used a stub that always answered. The stub was not a
neutral choice. Nothing in Wave 1+ can be trusted until real-provider behaviour
is in CI permanently.

---

## Wave 1 — Durability and data integrity

The audit chain *is* the product. It has to survive what actually happens to
storage.

| # | Item | Gate |
|---|---|---|
| 1.1 | **M12 — one ledger, not one chain per pod.** Segment, archive to object storage, merge, and reconcile | A verifier reconstructs the global chain from a cold start; a deliberate gap in sequence numbers is **detected**, not smoothed |
| 1.2 | **Unbounded log growth.** The audit file grows forever, and `M13` makes `/readyz` re-read all of it | `audit.jsonl` rotates on a schedule; `/readyz` uses a checkpoint and stays under 50ms at 10M records |
| 1.3 | **Key rotation must not break verification.** Rotating the HMAC key invalidates the chain it signed | Old and new key verify simultaneously during an overlap window; a rotation test proves no record becomes unreadable |
| 1.4 | **Clock skew.** Audit `ts` comes from the host clock | A skew beyond a threshold is *detected and reported*, not silently absorbed into the chain |
| 1.5 | **Postgres backup and restore** — today only the audit file has a drill | `pg_dump` → restore → row-count and checksum equality, on a schedule, unattended |
| 1.6 | **Retention.** Payloads are kept forever by default | A configured TTL is enforced in a test, and expiry is itself audited |

### 1.7 The design conflict nobody has resolved yet

The ledger is append-only and tamper-evident. Data-protection law requires
erasure on request. **Those two requirements are currently in direct conflict,
and the honest answer is that this is unsolved.**

A user asks for their data to be deleted. The chain says you cannot delete from
an immutable log. The chain wins, and the request goes unserved — or the chain
is edited, and the central claim is false.

The candidate answer is **crypto-shredding**: the payload is encrypted under a
per-tenant data key, erasure destroys the key, and the record survives as
evidence that *something* happened while the content is cryptographically gone.
That preserves both properties. It is not implemented, not specified, and needs
a named owner before any compliance conversation happens.

**Do not claim GDPR or "right to erasure" compliance until this has a gate.**

---

## Wave 2 — Behaviour under failure

The question a buyer asks is not "does it work" but "what happens when the
database is down at 9am on a Monday."

| # | Item | Gate |
|---|---|---|
| 2.1 | **Failover is a stub.** `echo` is a deterministic non-answer, not a fallback model | A second *real* provider is configured, and a fault-injection test kills the primary mid-request and asserts a real answer from the backup |
| 2.2 | **Postgres down** — what does a user see? | A defined answer (degraded read, or a clean `503` with a reason), tested by killing the database in a test, not by reasoning about it |
| 2.3 | **Redis down** — controls and rate limits are shared state | Documented, tested behaviour. Not "it falls back to per-process and the pause silently stops working across replicas" |
| 2.4 | **Graceful shutdown.** SIGTERM must drain in-flight requests and checkpoint | A test kills a process mid-request; in-flight requests complete or fail cleanly, and the chain is not left with a torn write |
| 2.5 | **M6 — blocking work on the event loop.** Audit append and synchronous embedding calls | A loadtest run at 3× the target shows no latency cliff; the embedding call is off the loop and the append path is benchmarked in CI |
| 2.6 | **Multi-replica load**, not single-process `echo` | A published number: throughput and p99 at N replicas, with the database and Redis in the path |
| 2.7 | **Limits everywhere** — request size, body size, concurrent streams, timeouts, retries with backoff, circuit-breaker thresholds | Each limit has a test at the boundary and one past it |

---

## Wave 3 — Security posture

| # | Item | Gate |
|---|---|---|
| 3.1 | **H7 — `/metrics` is tenant-readable** and series carry per-tenant labels. This is a cross-tenant disclosure | Restricted to `admin`, with a migration path for existing scrape configs and a documented break-glass for self-hosted users |
| 3.2 | **Secret lifecycle** — expiry, rotation, revocation. Nothing rotates today | A rotated secret takes effect without a redeploy, and the old one stops working on a schedule |
| 3.3 | **Tenant key rotation** with a dual-key overlap window, so rotation does not drop requests | A rotation test shows old and new keys both valid during overlap, old dead after |
| 3.4 | **Credential stuffing on `/admin/login`** — no rate limit today | Login attempts are rate-limited per source and per id; the test proves a run of guesses cannot succeed |
| 3.5 | **Session invalidation** — a password change must end existing sessions | Changing the password invalidates every issued session, tested |
| 3.6 | **H1/H2 — encrypted payloads.** "Prove what the AI said" requires `AEGIS_AUDIT_ENCRYPT_KEY`; without it the chain proves *that*, not *what* | A production-mode gateway without the key either refuses to boot or the claim is narrowed everywhere. Pick one; today the docs say the latter and the code allows the former |
| 3.7 | **Supply chain** — `pip-audit` or equivalent, Dependabot, pinned hashes, SBOM | Dependency audit runs in CI and blocks on a known CVE; an SBOM is generated per release |
| 3.8 | **Who read the log?** Reading the audit trail is itself an access that should be recorded | Reading `/admin/audit` cross-tenant writes a record |

---

## Wave 4 — Operational maturity

The difference between a product and a service.

| # | Item | Gate |
|---|---|---|
| 4.1 | **Structured JSON logs** with request-id correlation, exportable to a SIEM | A single `request_id` finds the full story in the log store; the format is a documented contract |
| 4.2 | **Distributed tracing** across the provider call | A trace shows gateway overhead and provider latency as separate spans |
| 4.3 | **SLOs and error budgets** | Published SLOs, alerts wired to them, and an error-budget policy that says what happens when it burns |
| 4.4 | **Runbooks** — the gateway is down, the chain is corrupt, a provider is compromised | Someone who did not build it can follow the runbook in a drill |
| 4.5 | **L6 — `ruff format`.** ~40 files never formatted; the check is non-blocking | Format check is blocking, in its own commit, not smuggled into a feature |

---

## Wave 5 — Claims that require money, time, or a third party

None of this is engineering, and all of it is what turns "solid" into
"auditable by someone who does not trust us".

| # | Item | Gate |
|---|---|---|
| 5.1 | **Independent penetration test** | A real report, triaged, with the findings public or at least summarised |
| 5.2 | **External security review** of the trust boundary — especially the trust placed in retrieved documents | Findings addressed or documented |
| 5.3 | **Signed, reproducible releases** with provenance | A consumer can verify a build from source; provenance is attested |
| 5.4 | **Sub-processor list and data-processing terms** for every model provider | Published, and the region each one processes in |
| 5.5 | **Data residency** — can a deployment be pinned to one region? | Documented and tested for the paths that make outbound calls |

**SOC 2 and ISO 27001 are organisation-level, not product-level.** Do not put
them on a product roadmap as if this codebase can achieve them. What this repo
*can* do is be the evidence an auditor samples.

---

## What is deliberately not on this list

Stated so they are not quietly added later:

- **A hosted SaaS.** It stays something you run yourself. That is the entire
  value for the air-gapped and regulated buyer.
- **A model.** It proxies. It does not fine-tune, host, or rank.
- **A chat product.** The console exists to make capabilities inspectable.
- **A blocker for compliance.** The soft-band waiver exists because a
  security product that refuses legitimate traffic gets switched off. It is
  rate-limited, audited, and deliberately has no hard-band equivalent. It stays.

---

## Sequencing, and what can run in parallel

```
Wave 0  deploy + real provider + weekly restore        ← everything depends on this
   │
   ├── Wave 1  durability, one ledger, key rotation, erasure design
   │
   ├── Wave 2  failure behaviour, graceful shutdown, multi-replica load
   │
   ├── Wave 3  security posture, /metrics, secret lifecycle
   │
   └── Wave 4  logs, tracing, SLOs, runbooks        ← can start once Wave 0 lands
                                                        
Wave 5  pen test, external review, signed releases  ← after 1-4, and not before
```

Waves 1, 2 and 3 are largely independent of each other and can be parallelised by
whoever is available. Wave 4 needs a real environment from Wave 0. Wave 5 needs
1–4 to be stable, because paying for a penetration test against a moving target
buys a report that is wrong by the time it lands.

---

## The shortest honest path to "production grade"

If the goal is a defensible claim rather than a complete product, this is the
minimum, in order:

1. **Deploy for real, against a real model, for 30 days** (Wave 0)
2. **Make `/metrics` admin-only** (3.1) — it is a live cross-tenant disclosure
3. **Rate-limit the admin login** (3.4) — it is an unthrottled credential oracle
4. **Prove key rotation** (1.3) — a product whose evidence key cannot be rotated
   without destroying the evidence is not deployable at 12-month intervals
5. **Build the global ledger** (1.1) — "tamper-evident" is currently per-pod, and
   this is the weakest point in the strongest feature
6. **Run an independent pen test** (5.1)
7. **Resolve the erasure conflict** (1.7) — before the first compliance
   conversation, not after

Items 2 and 3 are days of work. Items 1, 4, 5, 6 and 7 are the real project.

---

## Claims to stop making until the gates above close

Written down so a well-meaning README edit cannot re-introduce them:

| Do not say | Say |
|---|---|
| "tamper-proof" | "tamper-evident" — detectable, not resistant |
| "audit trail across your fleet" | "per-replica, until the global ledger lands" |
| "GDPR compliant" | nothing, until 1.7 has a design and a gate |
| "production ready" | "deployed, monitored and backed up, since \<date\>" — and only with a real date |
| "p95 0.6ms" | "0.6ms of gateway overhead on the `echo` path" — the real-provider number is 3–8s and both are true |
