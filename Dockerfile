FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# non-root runtime user
RUN groupadd -r aegis && useradd -r -g aegis aegis

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

USER aegis

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')" || exit 1

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
