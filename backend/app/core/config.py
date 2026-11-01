"""Application configuration management using Pydantic Settings."""

from typing import ClassVar, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for UniteCare Backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Known local development sentinel constants (used to guard production)
    DEV_DATABASE_URL: ClassVar[str] = (
        "postgresql+psycopg://unitecare_user:unitecare_secure_local_dev_password"
        "@localhost:5433/unitecare_db"
    )
    DEV_TEST_DATABASE_URL: ClassVar[str] = (
        "postgresql+psycopg://unitecare_user:unitecare_secure_local_dev_password"
        "@localhost:5433/unitecare_test_db"
    )
    DEV_JWT_SECRET_PLACEHOLDER: ClassVar[str] = (
        "replace_with_a_secure_random_64_character_hex_key_before_running"
    )

    # Application settings
    APP_NAME: str = "UniteCare API"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"

    # Server binding
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database configuration
    DATABASE_URL: str = DEV_DATABASE_URL
    TEST_DATABASE_URL: str = DEV_TEST_DATABASE_URL

    # Authentication & Security
    JWT_SECRET_KEY: str = DEV_JWT_SECRET_PLACEHOLDER
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_EXPIRE_DAYS: int = 30
    BCRYPT_ROUNDS: int = 12

    # Rate Limiting (process-local sliding window per client IP)
    # WARNING: InMemoryRateLimiter is process-local and does not share state across multiple workers or replicas.
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    RATE_LIMIT_REGISTER_PER_MINUTE: int = 5

    # CORS Configuration
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:8081",
    ]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, list):
            return v
        return []

    @model_validator(mode="after")
    def validate_production_settings(self) -> Self:
        """Enforce strict security requirements when running in production mode."""
        if self.ENVIRONMENT == "production":
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production environment.")

            if self.JWT_SECRET_KEY == self.DEV_JWT_SECRET_PLACEHOLDER:
                raise ValueError(
                    "JWT_SECRET_KEY must not use the development default placeholder in production."
                )

            if len(self.JWT_SECRET_KEY.strip()) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be at least 32 characters long in production."
                )

            is_dev_db = (
                self.DATABASE_URL == self.DEV_DATABASE_URL
                or "unitecare_secure_local_dev_password" in self.DATABASE_URL
                or "localhost" in self.DATABASE_URL
                or "127.0.0.1" in self.DATABASE_URL
            )
            if is_dev_db:
                raise ValueError(
                    "DATABASE_URL must not use the default local development database "
                    "configuration in production."
                )

        return self


settings = Settings()
