# Current status

This document separates implemented capability from deployment-specific claims.
The README describes the intended user and use case; the
[engineering case study](docs/RECRUITER-CASE-STUDY.md) explains the evidence.

## Available

- Public Render evaluation service with a company policy example, request console,
  API documentation and a recorded recruiter showcase.
- HTTP chat, non-streaming OpenAI-style completion, native streaming and
  tenant-scoped document ingestion/retrieval endpoints.
- Request screening across message roles, recognized-PII masking/restoration,
  tenant-scoped state, usage controls and provider fallback.
- Operator controls, retained audit verification and export surfaces.
- Isolated local showcase and seven reproducible engineering experiments.
- Automated verification, image build tooling and deployment configurations.

## Verification record

The latest recorded suite: **533 passed, 5 live-provider checks skipped**.
`make verify` includes lint, formatting, type checks, regression tests,
security/evaluation gates, deployment/document checks and recruiter evidence.
The seven evidence fixtures use recording/failing providers, not a language model.
Run the commands on the current commit before quoting a fresh result.

Public verification after PR #69 deployed confirmed the showcase and its assets,
fictional policy loading/retrieval, echo provider identity, email masking and a
supported attack refusal. That run established those requests at that time, not
continuous uptime or real-model quality.

## Boundaries and remaining work

| Area | Current boundary / next acceptance evidence |
|---|---|
| Real AI provider | Configure an external provider, pass live checks without skips, review answers and measure latency/cost |
| Company integration | Pilot with private scoped credentials, an approved corpus, defined error handling and a named operator |
| Identity | API-key tenant authentication exists; company SSO/user identity mapping is integration work |
| Screening and masking | Pattern-based; evaluate representative benign, adversarial and sensitive-input cases |
| Free hosting | Single-process evaluation, sleeping/ephemeral state; fictional policies reload at startup |
| Persistence and recovery | Exercise configured Redis/Postgres/object storage and backup/restore in the actual environment |
| Audit | Retained linked-record integrity; key handling, completeness and cross-replica ordering remain separate concerns |
| Delivery | Image build and manifest checks exist; Kubernetes deployment is not automatically applied to a company cluster |
| Production claims | Sustained real-provider operation and workload/incident drills are not established |

## Review history

The [archived review](docs/archive/CODE_REVIEW_AEGIS_GATEWAY.md) records findings
against an older commit and subsequent remediation. Its grades, counts and
benchmark runs are historical, not current headline metrics.

## Next steps

See the [roadmap](ROADMAP.md), [integration guide](docs/INTEGRATION.md),
[production-readiness plan](docs/PRODUCTION-READINESS.md) and
[operations runbook](docs/RUNBOOK.md).
