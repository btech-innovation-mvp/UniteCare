"""Unit tests for database Base, TimestampMixin, and Model Registry metadata."""

from sqlalchemy import Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.registry import target_metadata


class DummyAuditedModel(Base, TimestampMixin):
    """Temporary test model to verify TimestampMixin metadata."""

    __tablename__ = "test_dummy_audited_model"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)


def test_timestamp_mixin_metadata():
    """Verify TimestampMixin defines server_default and timezone-aware columns."""
    table = DummyAuditedModel.__table__

    created_at_col = table.c.created_at
    assert created_at_col.nullable is False
    assert created_at_col.type.timezone is True
    assert created_at_col.server_default is not None
    assert "now()" in str(created_at_col.server_default.arg).lower()

    updated_at_col = table.c.updated_at
    assert updated_at_col.nullable is False
    assert updated_at_col.type.timezone is True
    assert updated_at_col.server_default is not None
    assert "now()" in str(updated_at_col.server_default.arg).lower()


def test_model_registry_metadata_contains_models():
    """Verify target_metadata from registry reflects registered declarative tables."""
    assert "test_dummy_audited_model" in target_metadata.tables
    # Clean up test table from Base.metadata so it doesn't affect other inspections
    Base.metadata.remove(DummyAuditedModel.__table__)
    assert "test_dummy_audited_model" not in target_metadata.tables
