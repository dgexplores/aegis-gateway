#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== AEGIS setup =="

if [ ! -d .venv ]; then
  echo "→ creating venv .venv"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[dev]"

if [ ! -f .env ]; then
  echo "→ creating .env from .env.example"
  cp .env.example .env
  # generate random HMAC keys if still placeholder
  if grep -q "change-me" .env; then
    python3 -c "
import secrets
import pathlib
p=pathlib.Path('.env')
s=p.read_text()
s=s.replace('change-me-audit-hmac-key-min-32-chars', secrets.token_hex(32))
s=s.replace('change-me-vault-hmac-key-min-32-chars', secrets.token_hex(32))
p.write_text(s)
print('  generated HMAC keys')
"
  fi
  echo "  .env ready — edit GMI_API_KEY if you have one"
else
  echo "→ .env exists, keeping it"
fi

echo "→ verifying install"
python -c "import aegis; print('  aegis import ok')"
pytest -q 2>&1 | tail -1
echo ""
echo "Done. Run:"
echo "  source .venv/bin/activate"
echo "  uvicorn aegis.main:app --port 8080 --reload"
echo "  # or: make run"
echo "  # try: curl http://localhost:8080/healthz"
echo "  # auth: Authorization: Bearer demo-sk-aegis-2024  (demo tenant)"
