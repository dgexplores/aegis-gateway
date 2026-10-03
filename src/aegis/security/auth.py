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


class AmbiguousTenantKey(Exception):
    """Two tenants were configured with the same key hash.

    Refused at construction in every environment. A key that identifies two
    tenants is not a warning, it is a cross-tenant access bug waiting to be
    noticed by a customer.
    """


class Authenticator:
    def __init__(self, settings: Settings) -> None:
        self._by_key_hash: dict[str, Tenant] = {}
        # A key hash that belongs to two tenants is ambiguous, and this used to
        # resolve silently to whichever came last: `self._by_key_hash[hash] =
        # tenant` overwrites, so one tenant simply disappears and its callers get
        # another tenant's scopes and another tenant's documents. The symptom
        # would be "acme can read globex's data", reported weeks later with no
        # error anywhere to explain it.
        #
        # So an ambiguous key is refused at construction — in every environment,
        # not just production. A misconfiguration that cannot be resolved should
        # not be resolvable at all.
        owners: dict[str, str] = {}
        for tid, (key_hash, scopes) in settings.tenant_map().items():
            digest = key_hash.lower()
            claimed_by = owners.get(digest)
            if claimed_by is not None:
                raise AmbiguousTenantKey(
                    f"tenants '{claimed_by}' and '{tid}' share the same API key hash; "
                    "a key cannot identify two tenants, or the second one silently "
                    "inherits the first one's access. Mint a separate key per tenant "
                    "with scripts/gen_tenant.py."
                )
            owners[digest] = tid
            self._by_key_hash[digest] = Tenant(id=tid, scopes=frozenset(scopes))

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
