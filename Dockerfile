FROM python:3.14-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[backends]"

FROM python:3.14-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd -r aegis && useradd -r -g aegis aegis \
  && mkdir -p /data && chown aegis:aegis /data
COPY --from=builder /install /usr/local
COPY src ./src
ENV PYTHONPATH=/app/src AEGIS_AUDIT_PATH=/data/audit.jsonl
USER aegis
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')" || exit 1
CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
