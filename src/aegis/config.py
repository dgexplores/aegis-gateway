"""Central configuration. Fail-closed: missing critical secrets abort startup in production."""

import os
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV = "AEGIS_ENV"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    env: str = "development"
    host: str = "0.0.0.0"
    port: int = 8080

    audit_hmac_key: str = "dev-audit-key-not-for-production-usage!"
    vault_hmac_key: str = "dev-vault-key-not-for-production-usage!"

    tenants: str = "demo:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:chat,rag"

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
    max_input_tokens: int = 8000
    cache_ttl_seconds: int = 300

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
