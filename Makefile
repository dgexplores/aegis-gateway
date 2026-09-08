.PHONY: install setup dev test test-cov lint type security evals rag-eval verify run demo smoke docker-build docker-up gen-tenant check-secrets

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
	PYTHONPATH=src python scripts/eval_gate.py --dataset src/aegis/evals/golden.yaml --threshold 0.85

rag-eval:
	python scripts/rag_eval.py --baseline scripts/rag_baseline.json

verify: lint type test security evals rag-eval
	@echo "VERIFY OK — lint+type+tests+redteam+evals+rag green"

smoke:
	bash scripts/smoke.sh

check-secrets:
	bash scripts/check_no_secrets.sh

run:
	uvicorn aegis.main:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t aegis-gateway:latest .

docker-up:
	docker compose up -d
