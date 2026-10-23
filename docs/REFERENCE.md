# API and engineering reference

The [README](../README.md) explains the audience and policy-assistant use case.
The [integration guide](INTEGRATION.md) provides server-side setup, examples and
outcome handling. The deployed [OpenAPI documentation](https://aegis-gateway-free.onrender.com/docs)
exposes the current request schemas.

## Native request contracts

| Route | Input / behaviour |
|---|---|
| `POST /v1/chat` | `messages` with role/content, optional `max_tokens` and `use_cache`; no retrieval |
| `POST /v1/chat/completions` | OpenAI-style non-streaming envelope; server routing determines model |
| `POST /v1/chat/stream` | Native streaming events; separate from compatibility endpoint |
| `POST /v1/rag/ingest` | `source`, `text`; tenant-scoped text ingestion |
| `POST /v1/rag/query` | `question`; retrieves tenant context and invokes the pipeline |
| `GET /v1/rag/documents` | Lists the caller tenant's available documents |
| `POST /v1/rag/delete` | `source`; deletes that tenant's document |
| `GET /healthz`, `GET /readyz` | Liveness and configured readiness checks |

A native chat response includes `answer`, `blocked`, `provider`, injection
signals, masked types, routing metadata and available audit sequence information.
RAG adds retrieved citations. Debug outbound previews are not exposed in
production. A 200 response can carry a refusal or echo test output.

## Code entry points

- [Routes and schemas](../src/aegis/api/routes.py)
- [Request orchestration](../src/aegis/gateway.py)
- [Provider registry](../src/aegis/providers/registry.py)
- [Retrieval service](../src/aegis/rag/service.py)
- [Audit implementation](../src/aegis/security/audit.py)
- [Trust-boundary tests](../tests/test_trust_boundary.py)

## Evidence and operations

`make recruiter-evidence` records seven illustrative experiments using the real
pipeline and recording/failing providers. `make verify` runs the full local
verification gates. Recorded fixture results do not establish real-model answer
quality, uptime or complete protection.

[Architecture decisions](ARCHITECTURE.md) · [Current status](../STATUS.md) ·
[Runbook](RUNBOOK.md) · [Production readiness](PRODUCTION-READINESS.md) ·
[Historical review](archive/CODE_REVIEW_AEGIS_GATEWAY.md)

The previous reference mixed old product copy, benchmark runs and deployment
claims. Its earlier versions remain in Git history; current claims belong in
README/STATUS and reproducible verification records.
