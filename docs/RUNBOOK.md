# Operator runbook

What to do when something is wrong, and what not to do. Written for someone who
did not build this and is holding a pager.

Each entry: **what you see**, **what it means**, **what to do**, and — where it
matters — **what will make it worse**. The last part is the reason this exists:
most incident damage is done by the second reasonable-sounding action.

Everything here is a real code path. Where a step is not implemented yet, it
says so rather than describing a fiction.

---

## Before anything else: the kill switch

If the situation is *"the gateway is doing something wrong and you cannot fix it
in five minutes"*, stop reading this document and open `/admin` → **Controls**.

| Control | What it does | What it cannot do |
|---|---|---|
| **Kill switch** | Refuses every request from every tenant, before rate limiting and before any scan | Nothing. This is the blunt instrument and it is on purpose |
| **Pause a tenant** | Refuses one tenant's traffic. Documents, history and budget untouched | It does not delete anything |
| **Waive the soft band** | Stops one known-noisy caller being refused for *suspicious-looking* input | It **cannot** waive a hard injection block. No control anywhere can |
| **Breaker override** | Holds a provider's circuit open (stop retrying it) or closed (put a fixed one back) | It does not repair the provider |

Three things about the kill switch worth knowing before you reach for it:

- **Turning traffic back on never needs the break-glass secret.** An incident
  must not end with a gateway nobody can switch back on. If you locked the
  gateway out, `{"on": false}` still works from your session.
- **Turning it off does need the break-glass secret**, if one is configured. It
  is deliberately *not* the admin password, so a compromised portal session is
  not the same thing as the ability to halt every tenant.
- **A refused attempt is audited, not just a successful one.** If you see
  `control_kill_refused_breakglass` in the log, someone reached for that control
  from a session that should not have. Treat it as a security event, not a typo.

**Decisions live in Redis.** The Controls tab says **this pod only** when it
means it — that is, when Redis is unreachable. If you see that warning on a
multi-replica deployment, a pause you apply is not reaching the other pods and
it will vanish on restart. Fix Redis before relying on a pause.

---

## "The audit chain is corrupt"

**What you see.** `chain corrupt at seq=N` in `/admin/status`, on `/readyz`, in
the logs, or the gateway refuses to boot with `refusing to start: audit chain
corrupt`.

**What it means.** A record's HMAC did not recompute, or its `prev_hash` did not
match the record before it. The file no longer matches what the chain key says it
should contain. This is the alarm the product exists to raise, so do not silence it.

**Do this, in order:**

1. **Copy the file somewhere safe first.** `cp audit.jsonl audit.jsonl.broken`.
   Everything after this is a read-only investigation, and the one action that
   makes the problem permanent is "just fix it in place".
2. Check whether a previous key is still configured. Rotating
   `AEGIS_AUDIT_HMAC_KEY` without retaining the old value in
   `AEGIS_AUDIT_HMAC_KEY_PREVIOUS` produces exactly this message on every
   record the old key signed. **This is the most common cause by a wide margin,
   and it is not tampering** — it is a configuration mistake.
3. If it really is tampered: work out *which* record. `load_verified_records()`
   in `aegis.security.audit` verifies every line and names the sequence number.
   Compare `seq=N-1`'s `entry_hash` with `seq=N`'s `prev_hash` — a link break
   means a record was removed; a signature failure on a correctly linked record
   means a record was edited.
4. Preserve the file and rotate the key. `make prod-guard` will refuse a
   deployment whose keyring is wrong.

**What makes it worse:** editing the file to "fix" the link, truncating it to
"get it booting", or re-signing the tail. All three destroy evidence and leave
the chain looking intact. The failure is loud on purpose.

---

## "Answers are wrong" rather than "the gateway is down"

**What you see.** Answers that contradict the policy, answers citing a document
that does not say that, or a retrieval regression.

**Do this.** `make rag-eval` — it reports recall@4, MRR, and drift against the
committed baseline. If recall dropped, the corpus or the retriever changed, not
the model. The gate blocks a merge that regresses retrieval, so this is usually
visible in CI before it reaches an employee.

**What makes it worse:** raising the top-k and calling it fixed. More chunks
means more irrelevant context handed to the model, which makes grounding worse,
not better.

---

## "The gateway is down after a deploy"

**Check, in order:**

1. `/readyz` — `503` means it is still starting, has no provider, or the audit
   chain will not verify. The detail string says which.
2. `/healthz` — `200` means the process is alive, so this is not a crash.
3. The chain. A refused boot on audit is deliberate.

**If it is draining**, it is exiting on purpose: `SIGTERM` makes the pod refuse
new requests with `503` and `Retry-After`, finish what is in flight, and only
then close. That is a rolling deploy working, not a failure. If the drain
timeout is hit, the log says `shutdown drain timed out with N request(s) in
flight` and those requests' audit records may be partial.

---

## "A provider is down or rate-limiting us"

The gateway already does the ordinary thing: circuit breakers, ordered failover,
and `echo` as a last resort. If a request is failing rather than failing over:

1. `/admin` → **Overview** → *Providers & dependencies* shows each provider's
   breaker state and consecutive-failure count.
2. **Hold a provider open** on the Controls tab to stop retrying a broken one.
   This is the correct move for a provider that is genuinely down, and it
   removes the retry storm that makes an upstream problem worse.
3. **Hold it closed** to put a fixed provider back in service without waiting
   out the failure threshold.

**Warning about `echo`.** The fallback provider returns a deterministic
non-answer. It is not a model. Leaving `AEGIS_PROVIDERS=echo` in production
means the platform stays up while every answer is silently wrong. The k8s
manifest ships `echo` and says so in a comment; treat that as unfinished
configuration, not a working deployment.

---

## "Someone logged into the admin portal, or tried to"

**What to see.** In the audit chain: `admin_audit_read` for a read, and
`control_*` events carrying an operator id.

**Failed portal logins are deliberately not audited.** A failed login is not
evidence, and recording the attempted id would turn the chain into a way to
discover valid operator accounts. So the absence of a failed-attempt trail is
the intended behaviour, not a gap.

What you *do* get:

- **Reads of the audit trail are recorded** — scope, limit, whether it was
  cross-tenant, whether payloads were included. Never the records themselves.
- **Login attempts are rate limited** per source and per (source, id). A run of
  guesses gets `429` with `Retry-After`. A correct login clears the window, so a
  real operator who fumbles their password is not the one who gets locked out.
- **Changing the password ends every existing session immediately.** The cookie
  is bound to a fingerprint of the credential that minted it, so a rotation is
  also a revocation. There is no session list to invalidate by hand, and none
  needed.

If you suspect a compromise: change `AEGIS_ADMIN_PASSWORD` and restart. Every
issued session dies on the next request.

---

## "The chain is fine but the records look incomplete"

Two normal causes, both expected:

- **You are looking at a rotated file.** The chain rotates at
  `AEGIS_AUDIT_MAX_BYTES` (10MB default) and carries `head` into the new file, so
  one file is a *window*, not the whole history. With `AEGIS_AUDIT_S3_BUCKET` set,
  the rotated segment is uploaded and the path is in the logs.
- **You are looking at a truncated window on purpose.** `link_ok` reports
  `null` — *unknown*, never assumed — for the oldest row in a window whose
  predecessor was not read. That is a feature: reporting a link as good when it
  was not checked would be exactly the kind of quiet failure this product is
  built to avoid.

To see whether the history you are looking at is *whole*, read the `ledger`
block that `/admin/audit` returns alongside the rows:

```bash
curl -s localhost:8080/admin/audit -H "Authorization: Bearer $KEY" \
  | python3 -c 'import json,sys; l=json.load(sys.stdin)["ledger"]; print(json.dumps({k:l[k] for k in ("segments","chains","longest_chain","records","complete","cached","age_s")}, indent=2))'
```

`complete: true` means every segment verified and the sequence numbers are
contiguous — the trail has nothing missing. **`complete: false` is the signal to
act**, and the block tells you which way it broke:

| Field | Meaning when `complete` is false |
| --- | --- |
| `errors` | A segment could not be read or failed verification. Named by filename. |
| `starts_mid_sequence` | A chain whose predecessor is gone — `missing_before` records are missing ahead of it. |
| `seq_gaps` | A sequence break *inside* a chain: records missing between two verified ones. |

Two things to know before you trust it:

- **Multiple chains is normal.** Each replica writes its own chain, so a
  fleet legitimately reports one chain per pod. A lost segment looks identical
  to a second pod — the hash link breaks either way — which is why continuity
  is proven from the sequence counter instead.
- **`cached: true` means up to 30 seconds old.** Assembly hashes every record
  in every segment, so it is cached rather than recomputed per request. After an
  incident, re-read with `refresh=1` to force a fresh assembly.

Assembly runs on a timer (every 60s) and logs at `ERROR` when the ledger is not
continuous, so you should not have to be looking at the page to find out. The
same tick pulls archived segments back from S3, so a host that has pruned its
own disk does not report itself incomplete.

Two things still limit this. The ledger is still **per-replica**: there is no
sequence that is global across pods, so `complete` describes *this host's*
segments plus whatever archive it can reach — two replicas can each be
individually whole and jointly disagree. Fetching a sibling
replica's segments is **not yet** implemented — only the configured bucket is
pulled — so cross-pod reconciliation still needs a shared bucket. See `docs/PRODUCTION-READINESS.md` item 1.1.

The archive needs `pip install -e '.[archive]'`. Without boto3, setting
`AEGIS_AUDIT_S3_BUCKET` logs `audit s3 archive skipped` and uploads nothing —
which is safe (retention refuses to prune what was never archived) but means
`AEGIS_AUDIT_KEEP_SEGMENTS` and `AEGIS_AUDIT_KEEP_DAYS` will never free anything.
Both share the same gate: age alone never prunes an unarchived segment.

## Free-tier deployment (`render-free.yaml`)

No disk, no Redis, no Postgres — everything free, four degradations accepted:

- **Sleep.** The platform spins the service down after ~15 minutes idle; first
  request after sleep waits out a cold boot. Point a free uptime pinger at
  `/healthz` every 10 minutes to stay warm.
- **Amnesia.** Each boot starts with an empty audit file. Boot pulls archived
  segments back from S3 before serving (and the 60s reconciler keeps pulling),
  so history reassembles from the bucket — but the bucket is then the *only*
  copy. No bucket configured means no history survives a night.
- **Per-process limits.** Rate limits and budgets live in the single worker, so
  they are exact at one worker and silently multiply if you ever scale to two.
- **In-memory RAG.** The corpus dies with the process; re-ingest after cold
  boots, or run echo-only.

`make prod-guard` validates this blueprint too: no disk, no paid services, S3
entry present, never production without Redis.

---

## Rotating the audit signing key

The one operation where doing it in the wrong order destroys evidence.

```bash
# 1. Add the NEW key as current and KEEP the old one for verification.
AEGIS_AUDIT_HMAC_KEY=<new key>
AEGIS_AUDIT_HMAC_KEY_PREVIOUS=<old key>     # comma-separated, newest first

# 2. Deploy. New records are signed with the new key; every old record still
#    verifies. Check /admin -> Chain: rows read "previous:0" for anything the
#    old key signed.

# 3. Only once you no longer need to prove anything the old key signed:
AEGIS_AUDIT_HMAC_KEY_PREVIOUS=
```

**What makes it worse:** setting the new key and dropping the old one in the same
change. Every record the old key signed stops verifying immediately. The gateway
refuses to boot rather than serving, which is the right behaviour and a
surprising one if you have not seen it.

**How long to keep the old key:** as long as you might need to prove something it
signed. A year of records means a year of keys, or an archive you can no longer
verify.

---

## Things this runbook cannot help with yet

Stated so nobody wastes time looking for them:

- **The corpus and the rate-limit counters have no recovery story.** RAG is
  in-memory unless Postgres is configured, so documents are lost on restart.
  Redis counters rebuild empty.
- **The ledger is per-replica.** "Tamper-evident" is true per pod until
  `reconcile_segments` is scheduled.
- **Retention is not enforced.** Archived segments do not expire. There is no
  configured TTL.
- **A request interrupted mid-provider-call has no torn-write protection test.**
  The drain reduces the window; it does not prove the absence of a torn write.
- **Erasure conflicts with immutability, and it is unsolved.** Crypto-shredding
  is the candidate answer. Do not tell anyone this system is GDPR-compliant.

`docs/PRODUCTION-READINESS.md` has the full list, and every entry names the gate
that closes it.
