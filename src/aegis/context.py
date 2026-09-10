"""Shared request context: correlation id readable without HTTP imports.

The API middleware sets it per request; core code (gateway, audit) reads it
for log correlation. Default '-' covers evals, scripts, and tests running
outside HTTP.
"""

import contextvars

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "aegis_request_id", default="-"
)
