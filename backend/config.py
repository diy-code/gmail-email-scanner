# Phase 0 — Environment variable configuration
# Uses pydantic-settings (BaseSettings) so all env vars are validated at
# startup rather than silently defaulting to None mid-request (Decision D2).
#
# Required env vars (must be set before deployment or locally via .env):
#   VIRUSTOTAL_API_KEY
#   ABUSEIPDB_API_KEY
#   SAFE_BROWSING_API_KEY
#   OPENAI_API_KEY
#   API_KEY                 ← shared X-API-Key secret for add-on -> backend auth
#
# Optional (have sensible defaults):
#   APP_VERSION, LOG_LEVEL

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",          # load from .env for local dev; ignored on Cloud Run
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # --- External API keys ---
    virustotal_api_key: str = Field(default="", description="VirusTotal API key")
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API key")
    safe_browsing_api_key: str = Field(default="", description="Google Safe Browsing API key")
    openai_api_key: str = Field(default="", description="OpenAI API key")

    # --- Internal auth ---
    api_key: str = Field(default="", description="Shared secret for X-API-Key header validation")

    # --- App config ---
    app_version: str = Field(default="1.0.0")
    log_level: str = Field(default="INFO")

    # --- Signal engine timeouts (seconds) ---
    signal_timeout_seconds: float = Field(
        default=3.0,
        description=(
            "Per-signal HTTP timeout budget. "
            "Keeps total backend latency well under the 30s add-on execution limit."
        ),
    )

    # --- VirusTotal domain cap ---
    virustotal_max_domains: int = Field(
        default=3,
        description="Max unique domains to query per email to stay within 4 req/min free tier.",
    )

    # --- URL cap (enforced server-side in addition to client-side) ---
    max_urls_per_request: int = Field(default=10)


# Singleton — imported everywhere as `from config import settings`
settings = Settings()
