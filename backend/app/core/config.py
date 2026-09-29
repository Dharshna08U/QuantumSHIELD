from functools import lru_cache
import json
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./quantumshield.db"
    jwt_secret: SecretStr | None = None
    # This application uses a symmetric secret; never accept caller-selected algorithms.
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_minutes: int = Field(default=30, gt=0, le=1440)
    ai_service_url: str = "http://localhost:8001"
    blockchain_service_url: str = "http://localhost:4000"
    pqc_provider: Literal["oqs", "unavailable"] = "unavailable"
    pqc_private_key_path: str | None = None
    pqc_public_key_path: str | None = None
    pqc_kem_private_key_path: str | None = None
    pqc_recipient_public_key_path: str | None = None
    blockchain_provider: Literal["mock", "fabric", "disabled"] = "mock"
    blockchain_api_token: SecretStr | None = None
    integration_timeout_seconds: float = Field(default=3.0, gt=0, le=60)
    auto_remediation_enabled: bool = False
    kubernetes_provider: Literal["unavailable", "mock", "rest"] = "unavailable"
    kubernetes_api_url: str | None = None
    kubernetes_bearer_token: SecretStr | None = None
    kubernetes_ca_file: str | None = None
    kubernetes_remediation_enabled: bool = False
    kubernetes_allowed_namespaces: str = ""
    kubernetes_allowed_deployments: str = ""
    kubernetes_max_replicas: int = Field(default=10, ge=1, le=100)
    kubernetes_restart_threshold: int = Field(default=5, ge=1, le=1000)
    kubernetes_repeated_crash_count: int = Field(default=3, ge=1, le=1000)
    kubernetes_event_reasons: str = "FailedMount,FailedCreate,FailedScheduling,BackOff"
    kubernetes_watch_enabled: bool = False
    kubernetes_watch_interval_seconds: float = Field(default=30.0, ge=1, le=3600)
    kubernetes_verification_max_attempts: int = Field(default=5, ge=1, le=30)
    kubernetes_verification_delay_seconds: float = Field(default=2.0, ge=0, le=60)
    kubernetes_approval_ttl_minutes: int = Field(default=30, ge=1, le=10080)
    kubernetes_approval_separation_of_duties: bool = True
    demo_mode: bool = False
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            if value.lstrip().startswith("["):
                return json.loads(value)
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def validate_origins(cls, value: list[str]) -> list[str]:
        if not value or any(origin == "*" for origin in value):
            raise ValueError("CORS origins must be explicit; wildcard origins are not supported")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
