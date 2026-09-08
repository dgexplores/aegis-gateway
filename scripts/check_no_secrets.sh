#!/usr/bin/env bash
# Fail if real secrets sneaked into git history / worktree. Docs use placeholders only.
set -euo pipefail
cd "$(dirname "$0")/.."

# allowlisted placeholder patterns live in .env.example; real JWTs are long eyJ...
if git grep -nE "eyJ[A-Za-z0-9_-]{20,}" -- . ':!*.lock' ':!*.sarif' 2>/dev/null | grep -v example | grep -v README; then
  echo "real JWT-looking secret found — rotate + remove" >&2
  exit 1
fi
if [ -f .env ]; then
  echo "note: .env present locally (gitignored, ok)"
fi
# .env must never be tracked
if git ls-files | grep -qx ".env"; then
  echo ".env tracked — untrack now" >&2
  exit 1
fi
echo "secret check ok"
