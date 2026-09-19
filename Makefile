.PHONY: install setup dev test test-cov lint type security evals rag-eval pii-eval benign-eval fuzz prod-guard verify run demo smoke evidence docker-build docker-up gen-tenant check-secrets

install:
	pip install -e ".[dev]"

setup:
	bash scripts/setup.sh

dev: install
	pre-commit install || true

test:
	PYTHONPATH=src pytest -q

test-cov:
	PYTHONPATH=src pytest -q --cov=src --cov-report=term-missing --cov-fail-under=70

demo:  ## one-line smoke test against running gateway
	@echo "== demo: ingesting sample doc + querying =="
	curl -s http://localhost:8080/v1/rag/ingest \
	  -H "Authorization: Bearer demo-sk-aegis-2024" \
	  -H "Content-Type: application/json" \
	  -d '{"text":"Employees get 20 vacation days per year.","source":"hr.md"}' | python -m json.tool
	curl -s http://localhost:8080/v1/rag/query \
	  -H "Authorization: Bearer demo-sk-aegis-2024" \
	  -H "Content-Type: application/json" \
	  -d '{"question":"How many vacation days?"}' | python -m json.tool

gen-tenant:
	python scripts/gen_tenant.py --id demo --scopes chat+rag

lint:
	ruff check src tests scripts

type:
	mypy src

security:
	PYTHONPATH=src python scripts/redteam.py --corpus scripts/attacks.yaml

evals:
	AEGIS_RATE_LIMIT_PER_MIN=1000 PYTHONPATH=src python scripts/eval_gate.py --dataset src/aegis/evals/golden.yaml --threshold 0.85

rag-eval:
	python scripts/rag_eval.py --baseline scripts/rag_baseline.json

pii-eval:
	python scripts/pii_eval.py

benign-eval:
	python scripts/benign_eval.py

fuzz:
	PYTHONPATH=src python scripts/fuzz_attacks.py --count 200

verify: lint type test security evals rag-eval pii-eval benign-eval prod-guard
	@echo "VERIFY OK — lint+type+tests+redteam+evals+rag+pii+benign+prod-guard green"

prod-guard:  ## deploy artifacts shippable? (durable audit, probes, hardening, compose)
	python scripts/prod_guard.py

smoke:
	bash scripts/smoke.sh

# Capture a real evidence bundle from a live gateway and render it as a
# self-contained page (docs/capability-evidence.html). Boots its own server on a
# scratch port + audit file, so it never touches your dev instance or its chain.
#
# The server is started, exercised and torn down inside ONE shell: a background
# process does not survive the shell that launched it, so splitting these into
# separate invocations leaves the capture talking to a dead port.
evidence:
	@bash -c 'set -e; \
	  DIR=$$(mktemp -d); PORT=8098; \
	  AEGIS_ENV=development \
	  AEGIS_AUDIT_HMAC_KEY=evidence-audit-hmac-key-min-32-chars \
	  AEGIS_VAULT_HMAC_KEY=evidence-vault-hmac-key-min-32-chars \
	  AEGIS_AUDIT_ENCRYPT_KEY=evidence-payload-key \
	  AEGIS_AUDIT_PATH=$$DIR/audit.jsonl \
	  AEGIS_TENANTS="demo:e3e18b6e9c3d49198e61396c5e4439668591ec224bac1ef1c2736661d80763ef:chat+rag+admin" \
	  AEGIS_PROVIDERS=echo PYTHONPATH=src \
	  python -m uvicorn aegis.main:app --host 127.0.0.1 --port $$PORT > $$DIR/server.log 2>&1 & \
	  SRV=$$!; \
	  trap "kill $$SRV 2>/dev/null || true; rm -rf $$DIR" EXIT; \
	  for i in $$(seq 1 40); do \
	    curl -sf http://127.0.0.1:$$PORT/healthz >/dev/null 2>&1 && break; sleep 0.5; \
	  done; \
	  BASE=http://127.0.0.1:$$PORT KEY=demo-sk-aegis-2024 python scripts/capture_evidence.py; \
	  python scripts/build_evidence_report.py'

check-secrets:
	bash scripts/check_no_secrets.sh

run:
	uvicorn aegis.main:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t aegis-gateway:latest .

docker-up:
	docker compose up -d
