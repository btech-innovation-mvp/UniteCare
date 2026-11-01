"""Tests for database models, Alembic metadata discovery, and schema constraints."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.registry import target_metadata
from app.modules.auth.models import AuthIdentity, SessionStatus
from app.modules.auth.models import Session as UserSession
from app.modules.rbac.models import Role, UserRole
from app.modules.users.models import AccountStatus, User


def test_target_metadata_contains_all_stage3_tables():
    """Verify Alembic target_metadata discovers all 9 required Stage 3 tables."""
    expected_tables = {
        "users",
        "auth_identities",
        "sessions",
        "refresh_tokens",
        "security_events",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
    }
    actual_tables = set(target_metadata.tables.keys())
    assert expected_tables.issubset(actual_tables)


def test_user_functional_lower_email_unique_constraint(db_session: Session, random_email: str):
    """Verify PostgreSQL functional unique index on LOWER(email) blocks case variants."""
    user1 = User(email=random_email.lower(), account_status=AccountStatus.ACTIVE)
    db_session.add(user1)
    db_session.commit()

    # Attempt inserting same email with uppercase variant
    user2 = User(email=random_email.upper(), account_status=AccountStatus.ACTIVE)
    db_session.add(user2)
    try:
        db_session.commit()
        assert False, "Expected IntegrityError due to ix_users_lower_email index."
    except IntegrityError:
        db_session.rollback()


def test_cascade_delete_user(db_session: Session, random_email: str):
    """Verify cascade deletion of a User removes auth identities, sessions, and user roles."""
    user = User(email=random_email, account_status=AccountStatus.ACTIVE)
    db_session.add(user)
    db_session.commit()

    identity = AuthIdentity(user_id=user.id, provider="local", password_hash="dummy_hash")
    session = UserSession(
        user_id=user.id,
        status=SessionStatus.ACTIVE,
        expires_at=func.now(),
    )
    role = Role(name=f"test_role_{uuid.uuid4().hex[:6]}")
    db_session.add_all([identity, session, role])
    db_session.commit()

    user_role = UserRole(user_id=user.id, role_id=role.id)
    db_session.add(user_role)
    db_session.commit()

    # Delete the user
    db_session.delete(user)
    db_session.commit()

    # Assert cascaded deletes
    assert db_session.get(AuthIdentity, identity.id) is None
    assert db_session.get(UserSession, session.id) is None
    ur = db_session.execute(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    ).scalar_one_or_none()
    assert ur is None
    # Role itself should still exist
    assert db_session.get(Role, role.id) is not None
