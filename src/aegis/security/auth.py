"""Tenant authentication: hashed API keys + scoped authorization.

Keys are presented as `Authorization: Bearer sk-...` and verified against a
SHA-256 hash stored in config — the gateway never persists plaintext keys.
Timing-safe comparison throughout.
"""

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from aegis.config import Settings


@dataclass(frozen=True)
class Tenant:
    id: str
    scopes: frozenset[str]


class Authenticator:
    def __init__(self, settings: Settings) -> None:
        self._by_key_hash: dict[str, Tenant] = {}
        for tid, (key_hash, scopes) in settings.tenant_map().items():
            tenant = Tenant(id=tid, scopes=frozenset(scopes))
            self._by_key_hash[key_hash.lower()] = tenant

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def authenticate(self, request: Request) -> Tenant:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        presented_raw = auth.removeprefix("Bearer ").strip()
        if not presented_raw:
            # sha256("") is a well-known constant. If it ever appears in a tenant
            # list (it was the built-in default), an empty bearer token would
            # authenticate — so an empty credential is refused outright, before
            # the comparison loop, regardless of configuration.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="empty api key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        presented = self.hash_key(presented_raw)
        # timing-safe: compare against every stored hash, no early exit on dict miss
        matched: Tenant | None = None
        for stored_hash, tenant in self._by_key_hash.items():
            if hmac.compare_digest(presented.lower(), stored_hash.lower()):
                matched = tenant
        if matched is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api key")
        return matched
