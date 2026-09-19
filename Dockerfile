FROM python:3.14-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[backends]"

# --- release gate stage ------------------------------------------------------
# The prod CD job used to run `pytest` inside the *runtime* image, which has no
# pytest, no tests/ and no scripts/ — so the release gate exited 127 and every
# tagged release was blocked. This stage carries the dev deps and the corpus so
# the gate runs against the exact source that was built.
#
# It installs into /gatedeps, NOT /install: the runtime stage copies /install
# from `builder`, so writing dev tooling there would ship pytest/ruff/mypy into
# the production image. It also sits *before* `runtime` so that `docker build .`
# (no --target) still defaults to the runtime stage.
#
#   docker build --target gate -t aegis-gate:local .
#   docker run --rm aegis-gate:local
FROM builder AS gate
# --prefix installs land outside the interpreter's site dirs, so the gate
# console scripts (pytest, ruff, mypy) would fail with ModuleNotFoundError
# without this. Pinned: the base image is python:3.14-slim, so the path is stable.
ENV PATH=/gatedeps/bin:$PATH \
    PYTHONPATH=/app/src:/gatedeps/lib/python3.14/site-packages \
    AEGIS_ENV=test \
    AEGIS_AUDIT_PATH=/tmp/audit.jsonl \
    AEGIS_RATE_LIMIT_PER_MIN=1000 \
    AEGIS_PROVIDERS=echo
RUN pip install --no-cache-dir --prefix=/gatedeps ".[dev]"
COPY tests ./tests
COPY scripts ./scripts
COPY deploy ./deploy
# Repo-root deploy artifacts the suite asserts on (prod-guard, env-shape).
COPY docker-compose.yml Dockerfile render.yaml .env.example ./
CMD ["sh", "-c", "\
pytest -q \
&& python scripts/redteam.py --corpus scripts/attacks.yaml \
&& python scripts/eval_gate.py --dataset src/aegis/evals/golden.yaml --threshold 0.85 \
&& python scripts/rag_eval.py --baseline scripts/rag_baseline.json \
&& python scripts/pii_eval.py \
&& python scripts/benign_eval.py \
&& python scripts/prod_guard.py"]

FROM python:3.14-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd -r aegis && useradd -r -g aegis aegis \
  && mkdir -p /data && chown aegis:aegis /data
COPY --from=builder /install /usr/local
COPY src ./src
ENV PYTHONPATH=/app/src AEGIS_AUDIT_PATH=/data/audit.jsonl AEGIS_WORKERS=2
USER aegis
EXPOSE 8080
# Probe the port the process actually bound, not a hardcoded one: AEGIS_PORT /
# PORT (injected by most container platforms) would otherwise leave the
# container permanently "unhealthy" while it served traffic perfectly well.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 --start-period=10s \
    CMD python -c "import os,urllib.request; p=os.environ.get('AEGIS_PORT') or os.environ.get('PORT') or '8080'; urllib.request.urlopen('http://127.0.0.1:'+p+'/healthz')" || exit 1
# `aegis-gateway` is the console script for aegis.serve:main, which honours
# AEGIS_PORT/PORT. Multi-worker (AEGIS_WORKERS=2) needs the Redis the compose
# file and the K8s manifest both provide.
CMD ["aegis-gateway"]
