# AEGIS showcase: a company policy assistant with an inspectable gateway

## The sentence to lead with

“AEGIS helps developers and IT teams put access, privacy and audit controls around internal AI assistants. This policy assistant is one example: an employee asks a question, and we can inspect how the gateway handled it.”

The gateway is the product. The fictional Northstar Labs assistant is the demonstration. The intended first adopter is a technical team building an internal assistant; an employee is the assistant's user, not the gateway's administrator.

## Prepare once

From the repository, using Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python scripts/showcase.py
```

Open http://127.0.0.1:8080/dashboard. The launcher loads three fictional policies, creates a fresh local credential, and isolates the server from your existing .env, documents and audit files. No external services are needed. The credential is deliberately available to the local console, so the launcher binds only to loopback. Closing it removes its temporary state. Restart for a clean presentation.

### Public evaluation readiness

The published evaluation key in development mode loads missing fictional sample
policies at startup, including after a free-host cold start. Existing documents
with those source names are preserved. This never runs in production.
`AEGIS_DEMO_SEED_POLICIES=false` disables it; explicitly setting it to true can
opt another configured development demo tenant in.

### For actual AI answers

Export the chosen provider's API key in your terminal using your normal secret-management method. Keep it off screen. Then select that provider explicitly:

```bash
python scripts/showcase.py --provider openai
# Also supported: --provider anthropic or --provider gmi
```

The launcher checks that the corresponding OPENAI_API_KEY, ANTHROPIC_API_KEY or GMI_API_KEY is present. Requests use that provider's quota and may incur charges. The existing gateway can fall back to echo: always inspect the actual provider, not just the configured mode. The verification below fails if the selected provider did not serve both allowed requests.

```bash
python scripts/showcase.py --provider openai --check --report work/showcase-real.json
```

This verifies retrieval, masking, blocking and provider identity. Read the returned policy_answer and compare it with src/aegis/static/showcase-policies.json; successful transport and a citation do not establish answer correctness. Do not describe a real-model presentation as verified until this check and answer review succeed in your environment.

For a reproducible controls-only check:

```bash
python scripts/showcase.py --check --report work/showcase-echo.json
```

## For a technical interview

Use [the engineering case study](RECRUITER-CASE-STUDY.md) and run
`make recruiter-evidence`. Spend the technical portion on the observed provider
payload, poisoned context, failure injection and audit-copy alteration. The
policy assistant supplies the application context. This is the stronger path
for backend, security and AI platform discussions.

## A three-minute presentation

1. **Explain the problem (20 seconds).** “An internal assistant needs more than model access: who can use it, what leaves the application, and what happened when a request was refused.” Point to the employee → gateway → provider relationship on the landing page.
2. **Ask a policy question (45 seconds).** Open the console and select Vacation days. The fictional policy says 20 days per calendar year. With a real provider, compare its answer with the source. With echo, explicitly say “This is test output; we are demonstrating retrieval and gateway controls.” Open Show details and identify the provider and retrieved source.
3. **Show privacy handling (40 seconds).** Select Try privacy check. Inspect Show details → what the provider received. The fictional address should be replaced with an alias. Explain that recognized patterns are masked; this is not a promise to detect every sensitive detail.
4. **Show a refusal (35 seconds).** Select Try attack attempt. Inspect the refusal and absent outbound payload. This demonstrates one supported attack pattern, not universal injection protection. These guided control examples run independently, so they do not become policy context.
5. **Review evidence (30 seconds).** Open Admin. On the local launcher, the visit key is prefilled with operator scope. Review the Chain tab and verification results. In other deployments, use an appropriately scoped operator credential. A linked audit log detects supported alterations to retained records; it does not guarantee complete history or compliance.
6. **Close with the boundary (10 seconds).** “This is a working gateway prototype with a reproducible local showcase. A company pilot still needs its own credentials, documents, persistent storage and acceptance checks.”

## Readiness and onboarding

| Stage | What you can demonstrate | What must be verified separately |
|---|---|---|
| Offline showcase | Seeded policies, retrieval context, recognized-email masking, supported attack refusal, audit inspection | AI answer quality: echo does not generate answers |
| Real-provider showcase | The same journey through a configured external model | Actual provider identity, correct policy answer, latency and failure behaviour |
| Company pilot | One team's assistant under scoped access | Tenant/corpus configuration, persistence and restore, provider/data policy, real workload evaluation, operator ownership |

For a first pilot, choose one team, a small approved policy corpus, one model provider and a named operator. Generate scoped credentials rather than using a public demo key. Agree on representative questions and attack/PII cases, verify tenant boundaries, and exercise restart/restore before onboarding staff. Follow docs/PRODUCTION-READINESS.md for broader operational work. A multi-replica cluster is not necessary to demonstrate this single-process MVP.

## If something goes wrong on stage

- Port already occupied: restart with --port 8090 and open the printed URL.
- No documents: use the launcher URL and key; it seeds only its isolated showcase tenant. The public evaluation deployment loads these fictional policies on startup; refresh its document list after a cold start.
- Echo in real-provider mode: stop and fix the provider credentials/quota or connection; present controls-only if needed. Never call echo an AI-generated answer.
- Missing context: inspect the listed policies and ask the exact starter question first.
- A real-model answer is unsupported: show the source and acknowledge the mismatch. A retrieval citation is context, not proof of correctness.
- Need a clean start: Ctrl+C and relaunch. Temporary demo data resets.

## Wording for your portfolio

**Title:** AEGIS — an inspectable AI gateway for internal assistants

**Description:** Built a Python/FastAPI gateway with tenant access controls, request screening, recognized-PII masking, provider routing and linked audit records. Demonstrated the request lifecycle through a fictional company policy assistant, with a reproducible offline path and explicit real-provider verification.

**Development disclosure:** Developed with AI assistance. Discuss the code, trade-offs and evidence you can personally explain.

Avoid “enterprise-ready,” “prevents all data leaks,” “blocks every injection,” “compliant,” or “deployed at a company” without evidence supporting those specific claims.

## Verification recorded for this change

On 2026-10-22: the full local suite passed with **533 passed, 5 live-provider
checks skipped**. Ruff lint and format checks, mypy and JavaScript syntax checks
passed. The isolated echo HTTP journey passed retrieval, policy allowance,
provider identity, email masking and pre-provider attack refusal checks. Browser
walkthroughs confirmed the policy, privacy and attack examples. No external model
credentials were present, so real-provider answers were not verified.
