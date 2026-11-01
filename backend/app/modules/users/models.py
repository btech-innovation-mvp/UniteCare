"""Database models for user accounts and identity."""

import enum
import uuid

from sqlalchemy import Enum, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class AccountStatus(str, enum.Enum):
    """Account status lifecycle states."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DISABLED = "DISABLED"


class User(Base, TimestampMixin):
    """User account entity representing a single human or system actor."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    account_status: Mapped[AccountStatus] = mapped_column(
        Enum(AccountStatus, native_enum=False, length=32),
        nullable=False,
        default=AccountStatus.ACTIVE,
        server_default=AccountStatus.ACTIVE.value,
    )

    # Relationships
    identities: Mapped[list["AuthIdentity"]] = relationship(  # noqa: F821
        "AuthIdentity",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sessions: Mapped[list["Session"]] = relationship(  # noqa: F821
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    roles: Mapped[list["Role"]] = relationship(  # noqa: F821
        "Role",
        secondary="user_roles",
        primaryjoin="User.id == UserRole.user_id",
        secondaryjoin="Role.id == UserRole.role_id",
        back_populates="users",
    )

    __table_args__ = (Index("ix_users_lower_email", func.lower(email), unique=True),)
