"""Runtime configuration loaded from environment variables and .env."""

from __future__ import annotations

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide settings. Instantiate once at startup via get_settings()."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- API keys ---
    vt_api_key: SecretStr = Field(default=SecretStr(""), alias="VT_API_KEY")
    greynoise_api_key: SecretStr = Field(default=SecretStr(""), alias="GREYNOISE_API_KEY")
    abuseipdb_api_key: SecretStr = Field(default=SecretStr(""), alias="ABUSEIPDB_API_KEY")

    # --- Transport ---
    transport: str = Field(default="stdio", alias="TRANSPORT")
    http_host: str = Field(default="127.0.0.1", alias="HTTP_HOST")
    http_port: int = Field(default=8765, alias="HTTP_PORT")

    # --- Timeouts ---
    request_timeout_s: float = Field(default=10.0, alias="REQUEST_TIMEOUT_S")
    provider_timeout_s: float = Field(default=6.0, alias="PROVIDER_TIMEOUT_S")

    # --- Rate limiting ---
    provider_rate_limit_per_min: int = Field(default=60, alias="PROVIDER_RATE_LIMIT_PER_MIN")

    # --- Logging ---
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_full_indicators: bool = Field(default=False, alias="LOG_FULL_INDICATORS")

    @field_validator("transport")
    @classmethod
    def _validate_transport(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"stdio", "http"}:
            raise ValueError(f"transport must be 'stdio' or 'http', got {v!r}")
        return v

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        v = v.upper().strip()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid LOG_LEVEL: {v!r}")
        return v

    def provider_key_present(self, provider: str) -> bool:
        """Return True if an API key is configured for the given provider name."""
        mapping = {
            "virustotal": self.vt_api_key,
            "greynoise": self.greynoise_api_key,
            "abuseipdb": self.abuseipdb_api_key,
        }
        secret = mapping.get(provider)
        return bool(secret and secret.get_secret_value())


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached Settings instance, constructing it on first call."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_cache() -> None:
    """Test helper: clear the cached Settings so the next call re-reads env."""
    global _settings
    _settings = None
