"""Unit tests for the fail-closed test database allowlist guard.

Verifies:
1. Exact database name 'unitecare_test_db' is accepted.
2. Development database ('unitecare_db') is strictly rejected.
3. Production, neighbor ('transit-db'), and arbitrary database names are strictly rejected.
4. Validation operates purely via URL parsing without connecting to or mutating any database.
"""

from unittest.mock import patch

import pytest

from tests.conftest import EXACT_TEST_DB_NAME, validate_test_database_name


def test_guard_accepts_exact_test_db_name():
    """Verify that exact test database 'unitecare_test_db' passes validation."""
    valid_url = "postgresql+psycopg://unitecare_user:secret@localhost:5433/unitecare_test_db"
    result = validate_test_database_name(valid_url)
    assert result == EXACT_TEST_DB_NAME


@pytest.mark.parametrize(
    "invalid_url, expected_error_fragment",
    [
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5433/unitecare_db",
            "Configured database name 'unitecare_db' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5432/transit-db",
            "Configured database name 'transit-db' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5432/transit_db",
            "Configured database name 'transit_db' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@prod-db.internal:5432/unitecare_prod",
            "Configured database name 'unitecare_prod' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5433/test",
            "Configured database name 'test' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5433/my_test_db",
            "Configured database name 'my_test_db' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5433/unitecare_test_db_extra",
            "Configured database name 'unitecare_test_db_extra' is rejected",
        ),
        (
            "postgresql+psycopg://unitecare_user:secret@localhost:5433/",
            "Configured database name '' is rejected",
        ),
        (
            "",
            "TEST_DATABASE_URL is not configured or empty",
        ),
    ],
)
def test_guard_rejects_non_exact_database_names(invalid_url: str, expected_error_fragment: str):
    """Verify that any database name other than 'unitecare_test_db' raises ValueError."""
    with pytest.raises(ValueError, match="CRITICAL SAFETY VIOLATION") as exc_info:
        validate_test_database_name(invalid_url)
    assert expected_error_fragment in str(exc_info.value)


def test_guard_does_not_open_database_connections():
    """Verify validation operates strictly via URL parsing without opening database connections."""
    with patch("sqlalchemy.create_engine") as mock_engine, patch("psycopg.connect") as mock_connect:
        url = "postgresql+psycopg://unitecare_user:secret@localhost:5433/unitecare_test_db"
        validate_test_database_name(url)
        mock_engine.assert_not_called()
        mock_connect.assert_not_called()
