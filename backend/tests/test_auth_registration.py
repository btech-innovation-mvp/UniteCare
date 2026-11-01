"""Tests for user account registration API and service layer."""

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.modules.audit.models import SecurityEvent, SecurityEventType
from app.modules.auth.models import AuthIdentity
from app.modules.rbac.models import Role, UserRole
from app.modules.users.models import AccountStatus, User


def test_successful_registration(client: TestClient, db_session: Session, random_email: str):
    """Verify standard user registration creates User, AuthIdentity, assigns public_user role, and logs audit event."""
    password = "SecurePassword123!"
    response = client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": password},
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "id" in data
    assert data["email"] == random_email.lower()
    assert data["account_status"] == "ACTIVE"
    assert "password" not in data
    assert "password_hash" not in data

    # Verify database state
    user = db_session.execute(
        select(User).where(func.lower(User.email) == random_email.lower())
    ).scalar_one()
    assert user is not None
    assert user.account_status == AccountStatus.ACTIVE

    # Verify AuthIdentity with bcrypt hash
    identity = db_session.execute(
        select(AuthIdentity).where(AuthIdentity.user_id == user.id)
    ).scalar_one()
    assert identity.provider == "local"
    assert identity.password_hash.startswith("$2b$")
    assert password not in identity.password_hash

    # Verify public_user role assignment
    public_role = db_session.execute(select(Role).where(Role.name == "public_user")).scalar_one()
    user_role = db_session.execute(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == public_role.id)
    ).scalar_one_or_none()
    assert user_role is not None

    # Verify SecurityEvent was logged
    event = db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.user_id == user.id,
            SecurityEvent.event_type == SecurityEventType.ACCOUNT_REGISTERED.value,
        )
    ).scalar_one_or_none()
    assert event is not None


def test_registration_duplicate_email_conflict(client: TestClient, random_email: str):
    """Verify registering with an existing email returns 409 Conflict."""
    payload = {"email": random_email, "password": "SecurePassword123!"}
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == status.HTTP_201_CREATED

    # Duplicate exact email
    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in res2.json()["detail"]


def test_registration_email_case_insensitivity(client: TestClient, random_email: str):
    """Verify email normalization and functional uniqueness across case variations."""
    res1 = client.post(
        "/api/v1/auth/register",
        json={"email": random_email.upper(), "password": "SecurePassword123!"},
    )
    assert res1.status_code == status.HTTP_201_CREATED
    assert res1.json()["email"] == random_email.lower()

    # Attempt registration with lowercase version
    res2 = client.post(
        "/api/v1/auth/register",
        json={"email": random_email.lower(), "password": "SecurePassword123!"},
    )
    assert res2.status_code == status.HTTP_409_CONFLICT


def test_registration_invalid_email_format(client: TestClient):
    """Verify invalid email syntax is rejected with 422."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "SecurePassword123!"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_registration_password_too_short(client: TestClient, random_email: str):
    """Verify passwords shorter than 8 characters are rejected with 422."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": "short"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_registration_password_exceeds_72_bytes_rejected_without_truncation(
    client: TestClient, random_email: str
):
    """Verify passwords exceeding 72 UTF-8 bytes are rejected with 422 rather than silently truncated."""
    long_password = "A" * 73
    response = client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": long_password},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "72" in str(response.json())


def test_client_cannot_assign_arbitrary_role(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify client attempts to supply a 'role' in registration payload are rejected or ignored."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": random_email,
            "password": "SecurePassword123!",
            "role": "admin",
            "roles": ["admin", "superadmin"],
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    user_id = response.json()["id"]

    # Verify user only has public_user, NOT admin
    user_roles = (
        db_session.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
        .scalars()
        .all()
    )
    assert set(user_roles) == {"public_user"}


def test_registration_rate_limiting(client: TestClient):
    """Verify exceeding rate limit on registration endpoint returns HTTP 429 with Retry-After header."""
    from app.core.config import settings
    from app.core.rate_limit import limiter

    limiter.reset()
    try:
        limit = settings.RATE_LIMIT_REGISTER_PER_MINUTE
        # Exhaust registration limit
        for i in range(limit):
            res = client.post(
                "/api/v1/auth/register",
                json={"email": f"ratelimit_reg_{i}@example.com", "password": "SecurePassword123!"},
            )
            assert res.status_code == status.HTTP_201_CREATED

        # Next registration attempt must be blocked by rate limiter
        blocked_res = client.post(
            "/api/v1/auth/register",
            json={"email": "ratelimit_reg_blocked@example.com", "password": "SecurePassword123!"},
        )
        assert blocked_res.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Too many register attempts" in blocked_res.json()["detail"]
        assert "Retry-After" in blocked_res.headers
    finally:
        limiter.reset()
