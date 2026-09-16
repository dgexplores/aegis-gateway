"""Central configuration. Fail-closed: missing critical secrets abort startup in production."""

import hashlib
import os
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV = "AEGIS_ENV"

# sha256("") — the hash of an empty API key. It used to be the built-in demo
# tenant hash, which meant `Authorization: Bearer ` (nothing after the space)
# authenticated. Never accept it, and never ship it as a tenant key.
EMPTY_KEY_HASH = hashlib.sha256(b"").hexdigest()
# The key in .env.example / the dashboard placeholder. Fine for a local demo,
# never acceptable in a production tenant list.
DEMO_KEY_HASH = "e3e18b6e9c3d49198e61396c5e4439668591ec224bac1ef1c2736661d80763ef"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    env: str = "development"
    host: str = "0.0.0.0"
    port: int = 8080

    audit_hmac_key: str = "dev-audit-key-not-for-production-usage!"
    vault_hmac_key: str = "dev-vault-key-not-for-production-usage!"

    # No built-in tenant. A gateway with no configured tenant authenticates
    # nobody (fail-closed); `bash scripts/setup.sh` writes a real demo tenant
    # into .env, and `python scripts/gen_tenant.py --id acme --scopes chat+rag`
    # mints your own. A shipped default key would be a public credential.
    tenants: str = ""

    # Opt-in hardening: when False, a client-supplied `system` turn is rejected
    # with 400. Default True because OpenAI-compatible clients legitimately send
    # a system prompt — but note that every turn is scanned and PII-redacted
    # either way (see Gateway._scan_conversation / _redact_conversation), so a
    # system prompt is never a way past the gate.
    allow_client_system_prompt: bool = True

    providers: str = "echo"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    gmi_api_key: str = ""
    gmi_base_url: str = "https://api.gmi-serving.com/v1"
    gmi_model: str = "Qwen/Qwen3.8-27B"

    @model_validator(mode="after")
    def _fallback_gmi_env(self):  # type: ignore[no-untyped-def]
        # Accept both AEGIS_GMI_API_KEY (prefixed) and plain GMI_API_KEY / GMI_BASE_URL
        # — provider docs use the plain names.
        if not self.gmi_api_key:
            self.gmi_api_key = os.environ.get("GMI_API_KEY", "")
        if self.gmi_base_url == "https://api.gmi-serving.com/v1":
            self.gmi_base_url = os.environ.get("GMI_BASE_URL", self.gmi_base_url)
        if self.gmi_model == "Qwen/Qwen3.8-27B":
            self.gmi_model = os.environ.get("GMI_MODEL", self.gmi_model)
        return self

    rate_limit_per_min: int = 60
    daily_token_budget: int = 200_000
    injection_block_threshold: float = 0.7
    injection_soft_threshold: float = 0.35
    cache_ttl_seconds: int = 300

    audit_path: str = "audit.jsonl"
    audit_max_bytes: int = 10_000_000
    redis_url: str = ""
    database_url: str = ""
    # Per-tenant model allowlist: "acme:echo-economy+echo-premium;other:gpt-4o-mini".
    # Empty = allow all tiers. Enforced in Gateway route step, noted in reason.
    tenant_models: str = ""
    # Demo key pre-filled into the /dashboard key field. Development only — the
    # route substitutes it into the template solely when env != "production",
    # because /dashboard is unauthenticated and would otherwise serve a working
    # credential to anyone who can reach the port.
    demo_api_key: str = ""
    # Audit evidence: encrypted payload copies + S3 archive on rotation.
    # Empty encrypt key disables payload copies (hash-only, current behavior).
    audit_encrypt_key: str = ""
    audit_s3_bucket: str = ""
    audit_s3_prefix: str = "aegis-audit/"
    # Embeddings: legacy (default, zero-dep hash_vec path) | hash | gmi | openai.
    embed_provider: str = "legacy"
    embed_model: str = ""

    def require_production_secrets(self) -> list[str]:
        """Return fatal config problems when running with env=production."""
        problems: list[str] = []
        weak_markers = ("change-me", "dev-", "not-for-production")
        if self.env == "production":
            if any(m in self.audit_hmac_key.lower() for m in weak_markers):
                problems.append("AEGIS_AUDIT_HMAC_KEY is a development default")
            if any(m in self.vault_hmac_key.lower() for m in weak_markers):
                problems.append("AEGIS_VAULT_HMAC_KEY is a development default")
            if len(self.audit_hmac_key) < 32:
                problems.append("AEGIS_AUDIT_HMAC_KEY must be >=32 chars")
            if len(self.vault_hmac_key) < 32:
                problems.append("AEGIS_VAULT_HMAC_KEY must be >=32 chars")
            problems.extend(self._tenant_problems(self.tenant_map()))
        return problems

    @staticmethod
    def _tenant_problems(tenants: dict[str, tuple[str, set[str]]]) -> list[str]:
        """A production gateway with no usable tenant is a misconfiguration.

        Failing loudly at boot beats serving 401s to every caller, and beats the
        old behaviour of quietly accepting an empty bearer token because the
        built-in default tenant hash happened to be sha256("")."""
        problems: list[str] = []
        if not tenants:
            problems.append(
                "AEGIS_TENANTS defines no usable tenant "
                "(mint one with: python scripts/gen_tenant.py --id acme --scopes chat+rag)"
            )
            return problems
        for tid, (key_hash, _scopes) in tenants.items():
            if key_hash.lower() == EMPTY_KEY_HASH:
                problems.append(
                    f"AEGIS_TENANTS tenant '{tid}' uses sha256('') — an empty bearer token "
                    "would authenticate; mint a real key with scripts/gen_tenant.py"
                )
            elif key_hash.lower() == DEMO_KEY_HASH:
                problems.append(
                    f"AEGIS_TENANTS tenant '{tid}' uses the public demo key hash — "
                    "mint a real key with scripts/gen_tenant.py before deploying"
                )
        return problems

    def tenant_map(self) -> dict[str, tuple[str, set[str]]]:
        """Parse 'id:sha256key:scope1+scope2' entries into {tenant_id: (key_hash, scopes)}.

        Comma separates tenants; '+' separates scopes within one tenant."""
        out: dict[str, tuple[str, set[str]]] = {}
        for entry in self.tenants.split(","):
            parts = entry.strip().split(":")
            if len(parts) == 3:
                tid, key_hash, scopes = parts
                out[tid] = (key_hash, {s for s in scopes.split("+") if s})
        return out

    def model_allowlist(self) -> dict[str, set[str]]:
        """Parse tenant_models 'tid:m1+m2;tid2:m3' into {tenant: {models}}."""
        out: dict[str, set[str]] = {}
        for entry in self.tenant_models.split(";"):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            tid, models = entry.split(":", 1)
            out[tid.strip()] = {m.strip() for m in models.split("+") if m.strip()}
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
