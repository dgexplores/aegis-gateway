.PHONY: install dev test lint type security evals run docker-build docker-up

install:
	pip install -e ".[dev]"

dev: install

test:
	pytest -q

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
