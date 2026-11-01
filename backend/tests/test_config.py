"""Unit tests for application configuration management and production validation."""

import pytest
from sqlalchemy.engine import make_url

from app.core.config import Settings


def test_default_settings():
    """Verify default application settings are properly loaded in development mode."""
    settings = Settings()

    assert settings.APP_NAME == "UniteCare API"
    assert settings.ENVIRONMENT == "development"
    assert settings.DEBUG is False
    assert settings.API_V1_STR == "/api/v1"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15
    assert settings.REFRESH_TOKEN_EXPIRE_DAYS == 7
    assert settings.RATE_LIMIT_LOGIN_PER_MINUTE == 10
    assert settings.RATE_LIMIT_REGISTER_PER_MINUTE == 5
    assert isinstance(settings.BACKEND_CORS_ORIGINS, list)
    assert "http://localhost:3000" in settings.BACKEND_CORS_ORIGINS


def test_cors_origins_parsing():
    """Verify CORS origins string parsing behaves correctly."""
    # Comma-separated string format
    s1 = Settings(BACKEND_CORS_ORIGINS="http://example.com, https://app.example.com")  # type: ignore
    assert s1.BACKEND_CORS_ORIGINS == ["http://example.com", "https://app.example.com"]

    # Direct list format
    s2 = Settings(BACKEND_CORS_ORIGINS=["http://web.unitecare.org"])  # type: ignore
    assert s2.BACKEND_CORS_ORIGINS == ["http://web.unitecare.org"]


def test_database_url_configuration():
    """Verify database URL format and development parameters without exposing credentials."""
    settings = Settings()
    url = make_url(settings.DATABASE_URL)

    assert url.drivername == "postgresql+psycopg"
    assert url.host == "localhost"
    assert url.port == 5433
    assert url.database == "unitecare_db"
    assert url.username == "unitecare_user"
    # Never assert or print password in plain text


def test_production_settings_default_jwt_secret_rejected():
    """Verify production rejects the default JWT secret placeholder."""
    with pytest.raises(
        ValueError,
        match="JWT_SECRET_KEY must not use the development default placeholder in production",
    ):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY=Settings.DEV_JWT_SECRET_PLACEHOLDER,
            DATABASE_URL="postgresql+psycopg://prod_user:secret@prod-db.internal:5432/unitecare_prod",
        )


def test_production_settings_short_jwt_secret_rejected():
    """Verify production rejects JWT secrets with insufficient entropy (< 32 characters)."""
    with pytest.raises(
        ValueError,
        match="JWT_SECRET_KEY must be at least 32 characters long in production",
    ):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="short-secret-under-32-chars",
            DATABASE_URL="postgresql+psycopg://prod_user:secret@prod-db.internal:5432/unitecare_prod",
        )


def test_production_settings_debug_true_rejected():
    """Verify production refuses to start with DEBUG=True."""
    with pytest.raises(ValueError, match="DEBUG must be False in production environment"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=True,
            JWT_SECRET_KEY="a" * 32,
            DATABASE_URL="postgresql+psycopg://prod_user:secret@prod-db.internal:5432/unitecare_prod",
        )


def test_production_settings_dev_database_url_rejected():
    """Verify production refuses to start with the default local development database."""
    with pytest.raises(
        ValueError,
        match="DATABASE_URL must not use the default local development database configuration in production",
    ):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="a" * 32,
            DEBUG=False,
            DATABASE_URL=Settings.DEV_DATABASE_URL,
        )


def test_production_settings_valid_configuration_accepted():
    """Verify production succeeds with valid non-development secrets and configuration."""
    valid_prod = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        JWT_SECRET_KEY="production_high_entropy_secret_key_exceeding_32_characters_strictly",
        DATABASE_URL="postgresql+psycopg://prod_user:strong_prod_pass@prod-postgres.internal:5432/unitecare_prod",
    )
    assert valid_prod.ENVIRONMENT == "production"
    assert valid_prod.DEBUG is False
    assert len(valid_prod.JWT_SECRET_KEY) >= 32
