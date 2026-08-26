.PHONY: install setup dev test lint type security evals run demo docker-build docker-up gen-tenant

install:
	pip install -e ".[dev]"

setup:
	bash scripts/setup.sh

dev: install

test:
	pytest -q

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
	python scripts/redteam.py --corpus scripts/attacks.yaml

evals:
	python scripts/eval_gate.py --dataset src/aegis/evals/golden.yaml --threshold 0.85

run:
	uvicorn aegis.main:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t aegis-gateway:latest .

docker-up:
	docker compose up -d
