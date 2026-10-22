from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILES = (".env", "../.env")


class DbOnlySettings(BaseSettings):
    """Used by Alembic so migrations do not require the app secret."""

    model_config = SettingsConfigDict(env_file=_ENV_FILES, env_prefix="NEXOPS_", extra="ignore")
    database_url: str = "sqlite:///./nexops.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILES, env_prefix="NEXOPS_", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./nexops.db"
    secret_key: str  # required, no default on purpose
    access_token_minutes: int = 60
    cors_origins: list[str] = ["http://localhost:5173"]
    log_level: str = "INFO"
    metrics_enabled: bool = True

    # Recovery: only simulated mode exists. Real execution is intentionally not implemented.
    recovery_mode: Literal["simulated"] = "simulated"
    allow_self_approval: bool = False
    approval_ttl_minutes: int = 30

    # Deterministic detection thresholds
    detection_window_minutes: int = 10
    brute_force_threshold: int = 5
    service_down_consecutive: int = 3
    error_rate_threshold: float = 0.05
    latency_threshold_ms: float = 1000.0
    metrics_window_minutes: int = 30
    min_samples_for_rate_rules: int = 3
    suspicious_access_threshold: int = 10
    privilege_burst_threshold: int = 3
    correlation_lookback_minutes: int = 120

    @field_validator("secret_key")
    @classmethod
    def _validate_secret(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("NEXOPS_SECRET_KEY must be at least 32 characters")
        if value.lower().startswith("change-me") or "placeholder" in value.lower():
            raise ValueError("NEXOPS_SECRET_KEY is still a placeholder; generate a real one")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


def database_url_from_env() -> str:
    return DbOnlySettings().database_url
