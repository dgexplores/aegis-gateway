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
        presented = self.hash_key(auth.removeprefix("Bearer ").strip())
        tenant = self._by_key_hash.get(presented)
        if tenant is None or not hmac.compare_digest(presented, presented):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api key")
        return tenant

    def require_scope(self, tenant: Tenant, scope: str) -> None:
        if scope not in tenant.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"tenant '{tenant.id}' lacks scope '{scope}'",
            )
