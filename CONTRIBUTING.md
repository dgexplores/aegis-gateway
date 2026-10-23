# Contributing

Start with the [README](README.md), [integration guide](docs/INTEGRATION.md) and
[current status](STATUS.md). Keep changes focused and use fictional fixtures.

## Local verification

Use Python 3.11 or newer and install `pip install -e '.[dev]'` in a virtual
environment. Run `make verify` before submitting a change. It includes formatting,
linting, types, tests, evaluations, deployment/document checks and evidence
experiments. Live-provider tests need explicit configuration and may incur
provider charges; a skipped live test does not establish provider compatibility.

## Pull requests

Explain the problem, resulting behaviour and validation. Add regression coverage
for meaningful boundary or failure-behaviour changes. Update documentation and
verification records together. State external dependencies that were not tested.
Describe AI assistance accurately; source and reproducible evidence matter.

## Repository hygiene

Do not commit `.env` files, credentials, private certificates, request/audit logs,
company corpora, local virtual environments or generated scratch outputs. Keep
public examples fictional and distinguish recorded evidence from live results.
Store scratch outputs under `work/`; only intentionally reviewed example evidence
belongs in `docs/`. Never suppress a secret finding just to make CI pass.

Report security issues using [SECURITY.md](SECURITY.md).
