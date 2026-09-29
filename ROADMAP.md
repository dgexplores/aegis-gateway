# Roadmap

What this project is trying to become, and how we will know it got there.

Three objectives, ordered. Each one is a gap that a buyer — or a reviewer — can
point at and say "that is not proven yet". `STATUS.md` holds the full findings
list; this file holds the direction.

The bar for everything here: **a claim is only made if a gate measures it.**
That rule is why some numbers in this repo are deliberately small today.

**If the question is "how do we make this production grade" rather than "what
should it become", read [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md).
It carries the wave-by-wave plan, the gate that closes each item, what is
blocked on something other than work, and — deliberately — a table of claims
this project must stop making until those gates close.

---

## Objective 1 — Make the quality gates actually measure quality

**Why.** The eval gates pass because the capability is good, but the sample sizes
are still too small to prove it. A retrieval score over 58 queries can be
carried by one lucky document, and 12 injection vectors cannot describe an
attack surface. This is the single highest-value investment in the project, and
it is **data, not code**.

**How we know we are done.**

| Gate | Now | Done when |
|---|---|---|
| PII eval | 207 cases, ≥20 per type — **done** | ≥ 20 cases per type, and the gate goes **blocking** on a precision regression |
| Benign FP | 200 cases, 0 false positives — **done** | ≥ 200 benign prompts; gate reports a false-positive rate and blocks above a set threshold |
| Retrieval | 52 documents, 58 grounded queries — query count missing | ≥ 50 documents, ≥ 200 queries; drift gate blocks on a recall@4 drop over 2 points |
| Injection | 12 vectors, no bands | ≥ 40 vectors across 3 bands, including encoded, multi-turn and role-tag smuggling |

The first two are the priority. **A gateway that blocks legitimate traffic gets
switched off**, and today we cannot prove it does not.

**Status.** Partly landed (`412a880`, then the benign corpus). PII depth, the
retrieval document count and benign scale are done. Next is the grounded query
count, then banded injection vectors.

One caveat carried forward: these corpora are hand-authored, not sampled from
production traffic, and every number is measured against the `echo` stub.

---

## Objective 2 — One ledger, not one chain per pod

**Why.** The audit chain is the product. Today each replica owns its own file, so
"tamper-evident" is true *per pod* — and reconciling N chains is a manual job. An
enterprise buyer will ask "show me the full history across your fleet" and the
honest answer today is "reconcile the pods yourself". That is the weakest point
in the strongest feature.

**How we know we are done.** Records from all replicas land in one append-only
store, and a verifier reconstructs and re-verifies the global chain from a cold
start. A gap in sequence numbers is detected and reported, not smoothed over.
Multi-pod reconciliation stops being a manual procedure and becomes a test.

**Design notes.** Already sketched: an S3-compatible object archive with
per-replica segments plus a merge step. The merge must preserve the property that
`link_ok` is reported as *unknown* rather than assumed when a window is
truncated — that behaviour is a feature and must survive the merge.

**Status.** Segments and per-replica rotation exist. Global reconcile does not.

---

## Objective 3 — Turn the evidence into an artifact a customer can hand out

**Why.** Every other project in this space gives you a dashboard. AEGIS can give
you **evidence** — and that is the differentiator, but right now it only exists as
a screen. A signed, human-readable, independently checkable audit report turns
"trust us" into "verify this". For the regulated buyer this *is* the product.

**How we know we are done.**

- A report renders one request's full evidence: verdict, score, signals, exactly
  what the provider received, exactly what the caller received, and the audit
  record with its signature.
- It carries the verification steps, and `scripts/verify_audit.py` — run
  standalone, no gateway needed — confirms or denies the chain offline.
- It is printable. Regulated buyers print these.

**Status.** The data all exists (`/admin/audit`, the evidence panel, NDJSON
export). What is missing is the report, the offline verifier, and a print
stylesheet. This is the highest ratio of perceived value to work in the project.

---

## Also on the list

Not objectives, but tracked and real:

- **Throughput ceiling** (M6) — audit append and the embedding call block the
  event loop. Fine at demo scale, a ceiling in production.
- **`/metrics` is tenant-readable** (H7) — cross-tenant series disclosure. Needs
  a deliberate rollout because tightening it breaks existing scrape configs.
- **Stale-chunk policy** (M10) — a re-ingested document can leave old chunks
  behind.
- **Real-provider numbers** — every latency figure in this repo is measured on
  `echo`. A p95 on a real model, and the gateway's overhead on top of it, is a
  number a buyer will ask for and we cannot yet give.
- **`ruff format`** (L6) — ~40 files never formatted. The check is non-blocking
  and making it blocking is a large unrelated diff.

---

## Non-goals

Stated so they are not quietly added later:

- **A hosted SaaS.** This stays a thing you run yourself. That is the whole point
  for the air-gapped and regulated buyer.
- **A model.** It proxies. It does not fine-tune, host, or rank.
- **A chat product.** The console exists to make capabilities inspectable. It is
  not the product.

---

## How to read the current state

| | |
|---|---|
| `README.md` | what it does, and what it looks like |
| `STATUS.md` | what is done, what is verified, what is open — the honest handover |
| `docs/ARCHITECTURE.md` | ADRs, failure modes, SLOs |
| `docs/PLAN.md` | phase history, CI gate design, per-PR checklist |
| `CODE_REVIEW_AEGIS_GATEWAY.md` | the senior review and its remediation log |
| Capability tour | `make evidence`, or run it live in `/dashboard` — 10 checks, graded against the live API |
