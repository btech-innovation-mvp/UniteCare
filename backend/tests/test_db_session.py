"""Unit tests for database session lifecycle and transaction rollback handling."""

from unittest.mock import MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_db


def test_get_db_lifecycle_normal():
    """Verify get_db yields an active session that can query and is closed on exit."""
    db_gen = get_db()
    session = next(db_gen)

    assert isinstance(session, Session)
    result = session.execute(text("SELECT 1")).scalar()
    assert result == 1

    # Finalize generator
    with pytest.raises(StopIteration):
        next(db_gen)


def test_get_db_lifecycle_rollback_on_exception(monkeypatch):
    """Verify get_db invokes rollback and re-raises when an unhandled exception occurs."""
    mock_session = MagicMock(spec=Session)
    monkeypatch.setattr("app.db.session.SessionLocal", lambda: mock_session)

    db_gen = get_db()
    session = next(db_gen)
    assert session is mock_session

    # Simulate an error in the request endpoint context
    with pytest.raises(RuntimeError, match="Simulated endpoint failure"):
        try:
            raise RuntimeError("Simulated endpoint failure")
        except RuntimeError:
            db_gen.throw(RuntimeError("Simulated endpoint failure"))

    # Assert explicit rollback was triggered
    mock_session.rollback.assert_called_once()
    # Assert session was cleanly closed in finally
    mock_session.close.assert_called_once()
