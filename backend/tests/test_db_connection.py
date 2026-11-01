"""Unit and integration tests for the non-destructive database connectivity utility."""

from unittest.mock import MagicMock

from sqlalchemy.exc import OperationalError

from app.db.check_connection import check_database_connection


def test_check_database_connection_live_success():
    """Verify check_database_connection succeeds against the active UniteCare PostgreSQL container."""
    result = check_database_connection()
    assert result is True


def test_check_database_connection_failure_handled_safely(monkeypatch):
    """Verify check_database_connection handles connection failures safely and returns False."""
    mock_engine = MagicMock()
    mock_engine.connect.side_effect = OperationalError("connection refused", None, None)

    monkeypatch.setattr("app.db.check_connection.engine", mock_engine)

    result = check_database_connection()
    assert result is False
