"""Shared pytest fixtures and test setup with strict database isolation and fail-closed safeguards."""

import uuid
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.main import app
from app.modules.rbac.service import ensure_system_rbac_seeds

EXACT_TEST_DB_NAME = "unitecare_test_db"


def validate_test_database_name(db_url: str) -> str:
    """Validate that the test database URL points strictly and exactly to the allowed test database.

    Raises ValueError if database name is not exactly 'unitecare_test_db'.
    Performs pure URL string parsing without opening any network or database connection.
    """
    if not db_url or not isinstance(db_url, str):
        raise ValueError("CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL is not configured or empty.")

    parsed_url = make_url(db_url)
    dbname = parsed_url.database or ""

    if dbname != EXACT_TEST_DB_NAME:
        raise ValueError(
            f"CRITICAL SAFETY VIOLATION: Test database name must be exactly '{EXACT_TEST_DB_NAME}'. "
            f"Configured database name '{dbname}' is rejected. Automated tests refuse to run against any other database."
        )
    return dbname


# Fail-closed safeguard: Validate test database identity before any test execution
try:
    validate_test_database_name(settings.TEST_DATABASE_URL)
except ValueError as _exc:
    pytest.exit(str(_exc), returncode=1)


# Dedicated isolated test engine connected strictly to unitecare_test_db
test_engine = create_engine(
    settings.TEST_DATABASE_URL,
    pool_pre_ping=True,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def initialize_test_database_seeds():
    """Ensure baseline system roles and permissions exist in unitecare_test_db once per session."""
    with TestSessionLocal() as session:
        ensure_system_rbac_seeds(session)
        session.commit()


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Provide an isolated database session per test using a transaction savepoint.

    All mutations (including inner endpoint commits) are scoped to a savepoint
    and cleanly rolled back at teardown without global table deletions.
    """
    connection = test_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient bound to the isolated savepoint test session."""

    def _override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    limiter.reset()  # Reset rate limit buckets between tests

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def random_email() -> str:
    """Generate a unique random test email address to ensure test isolation."""
    return f"test_{uuid.uuid4().hex[:10]}@unitecare-test.org"
