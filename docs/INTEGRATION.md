# Integrate AEGIS with an application or workflow

## Choose the boundary

Run AEGIS as a service behind your application's backend. Your existing app
handles company login and user permissions, then maps an authorized request to
a scoped AEGIS tenant key. AEGIS does not supply company SSO or a browser login
SDK for employees.

```text
Website / portal / HTTP workflow
        -> your authenticated backend
        -> AEGIS API (scoped tenant key)
        -> configured AI provider
        -> response and decision metadata
```

Keep the AEGIS key on the server. Provider keys belong in AEGIS's private runtime
configuration. Do not copy the public demo credential into a company deployment.

## Start a controlled pilot

1. Deploy the gateway privately with your chosen persistence configuration.
2. Generate a scoped entry with `python scripts/gen_tenant.py --id company --scopes chat+rag`.
   Store its printed key securely and configure its hashed `AEGIS_TENANTS` entry.
   Use a separate operator credential for admin capabilities.
3. Configure an external provider in the gateway's environment and verify that
   responses identify that provider. Follow the provider setup in
   [SHOWCASE.md](SHOWCASE.md); echo fallback is not an intelligent answer.
4. Set `AEGIS_BASE_URL` and `AEGIS_API_KEY` in your application's server environment.
5. Use the examples below with fictional data first. Review refusal/error handling,
   tenant isolation and approved-document retrieval before onboarding users.

A one-process pilot and a multi-replica production service have different
operational requirements. See [production readiness](PRODUCTION-READINESS.md).

## Backend chat example

```python
import os
import httpx

response = httpx.post(
    os.environ['AEGIS_BASE_URL'].rstrip('/') + '/v1/chat',
    headers={'Authorization': 'Bearer ' + os.environ['AEGIS_API_KEY']},
    json={'messages': [{'role': 'user', 'content': 'Explain our leave policy.'}]},
    timeout=40,
)
response.raise_for_status()
result = response.json()
if result['blocked']:
    # Display the refusal instead of treating it as a successful model answer.
    print(result['answer'])
elif result['provider'] == 'echo':
    # In a real assistant, show a defined degraded/unavailable state.
    print('The configured AI service did not produce this response.')
else:
    print(result['answer'])
```

[Runnable server-side example](../examples/website_backend.py). Run it only
against a deployment you control or the intentionally public fictional-data demo.

`/v1/chat` has no document retrieval. To answer from a company corpus:

```bash
curl --fail-with-body "$AEGIS_BASE_URL/v1/rag/ingest" \
  -H "Authorization: Bearer $AEGIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source":"fictional-leave.md","text":"Fictional staff receive 20 vacation days per year."}'

curl --fail-with-body "$AEGIS_BASE_URL/v1/rag/query" \
  -H "Authorization: Bearer $AEGIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"question":"How many vacation days are available?"}'
```

Ingest is a corpus-administration action. Do not expose it to every website
visitor. Citations identify retrieved context; review whether the answer is
supported. Ingest accepts text, not arbitrary PDF/file uploads or a company-drive
connector. Extract and approve text in your own controlled ingestion workflow.

## HTTP workflow tools

Use a server-side HTTP request step with method `POST`, URL
`<AEGIS_BASE_URL>/v1/chat` or `/v1/rag/query`, JSON body as above, and a Bearer key
from the workflow's secret store. Branch on `blocked`, `provider`, and HTTP
errors. These are generic HTTP integrations; this repository does not ship
native n8n, Zapier, Slack or company-directory connectors.

## OpenAI-style clients

Point a non-streaming client at `<AEGIS_BASE_URL>/v1` with the tenant key. The
completion endpoint returns `choices` and `usage`, and marks refusals with
`finish_reason: content_filter`.

Compatibility is intentionally bounded:

- `model` is required by the request schema but does not choose the downstream
  provider/model; server-side routing determines the actual model.
- `stream=true` is rejected by `/v1/chat/completions`.
- The native `/v1/chat/stream` endpoint has its own event format; it is not a
  promise of OpenAI-compatible streaming.
- The compatibility response does not expose all native decision metadata. Use
  `/v1/chat` when your UI needs the gateway's `blocked`/`provider` fields.

## Handle outcomes explicitly

| Outcome | Application behaviour |
|---|---|
| HTTP 200, `blocked=true` | Display refusal; do not treat HTTP success as model success |
| HTTP 200, `provider=echo` | Label a test/degraded response; do not present it as AI reasoning |
| HTTP 401 / 403 | Check server credential, tenant mapping and required scopes |
| HTTP 402 | Usage budget exhausted; surface an appropriate limit message |
| HTTP 429 | Respect `Retry-After`; avoid an uncontrolled retry loop |
| HTTP 503 | Surface unavailable/degraded state and use bounded retries where appropriate |

Native debug outbound previews are disabled in production. Never require them
for the normal employee UI. Your logging should avoid request content and keys.

## Acceptance before company use

Verify a real provider and representative policy answers; use private credentials,
approved corpora and defined user-to-tenant mapping; test persistence and restore;
assign an operator; exercise refusal, outage and limit behaviour. The public
Render demo and the recorded evidence report do not establish this acceptance.
