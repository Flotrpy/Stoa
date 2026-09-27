"""Validated application settings with environment-variable support."""

from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings shared by the local server entry point."""

    model_config = SettingsConfigDict(
        env_prefix="STOA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8787, ge=1, le=65535)
    database_url: str = "postgresql+psycopg://stoa:change-me@127.0.0.1:5432/stoa"
    auth_secret: SecretStr = SecretStr("development-only-change-me-32-bytes")
    access_token_minutes: int = Field(default=30, ge=5, le=1440)
    log_level: str = "INFO"

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Reject known development secrets in production mode."""

        secret = self.auth_secret.get_secret_value()
        if self.env == "production" and (secret.startswith("development-") or len(secret) < 32):
            raise ValueError("production STOA_AUTH_SECRET must be a unique 32+ character value")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return one immutable-by-convention settings instance per process."""

    return Settings()
