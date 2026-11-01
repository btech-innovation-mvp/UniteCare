"""Tests for login authentication, JWT access token issuance, and session generation."""

import jwt
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_refresh_token
from app.modules.audit.models import SecurityEvent, SecurityEventType
from app.modules.auth.models import RefreshToken, SessionStatus
from app.modules.auth.models import Session as UserSession
from app.modules.users.models import AccountStatus, User


def test_successful_login(client: TestClient, db_session: Session, random_email: str):
    """Verify login returns short-lived access JWT, high-entropy refresh token, and creates active session."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": password},
    )
    assert reg_res.status_code == status.HTTP_201_CREATED
    user_id = reg_res.json()["id"]

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": random_email, "password": password},
    )
    assert login_res.status_code == status.HTTP_200_OK
    data = login_res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Verify JWT claims minimalism
    payload = jwt.decode(
        data["access_token"],
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    assert payload["sub"] == user_id
    assert "sid" in payload
    assert "jti" in payload
    assert "iat" in payload
    assert "exp" in payload
    # Must NOT contain passwords, sensitive profiles, or bulky roles
    assert "roles" not in payload
    assert "permissions" not in payload
    assert "password" not in payload

    # Verify session in DB
    session = db_session.get(UserSession, payload["sid"])
    assert session is not None
    assert session.status == SessionStatus.ACTIVE
    assert str(session.user_id) == user_id

    # Verify refresh token in DB: only SHA-256 hash is stored, NEVER the raw token
    raw_rt = data["refresh_token"]
    expected_hash = hash_refresh_token(raw_rt)
    token_record = db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == expected_hash)
    ).scalar_one_or_none()
    assert token_record is not None
    assert token_record.session_id == session.id
    assert token_record.used_at is None
    assert token_record.revoked_at is None

    # Check security events logged
    events = (
        db_session.execute(select(SecurityEvent.event_type).where(SecurityEvent.user_id == user_id))
        .scalars()
        .all()
    )
    assert SecurityEventType.LOGIN_SUCCESS.value in events
    assert SecurityEventType.SESSION_CREATED.value in events


def test_login_wrong_password_generic_error(client: TestClient, random_email: str):
    """Verify wrong password returns 401 with generic error message."""
    client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": "CorrectPassword123!"},
    )
    res = client.post(
        "/api/v1/auth/login",
        json={"email": random_email, "password": "WrongPassword999!"},
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert res.json()["detail"] == "Invalid email or password."


def test_login_unknown_email_generic_error(client: TestClient):
    """Verify unknown email returns 401 with generic error message without leaking user existence."""
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent_actor_9999@example.com", "password": "AnyPassword123!"},
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert res.json()["detail"] == "Invalid email or password."


def test_login_suspended_account_rejected(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify suspended accounts cannot log in."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": password},
    )
    user_id = reg_res.json()["id"]

    # Suspend user
    user = db_session.get(User, user_id)
    user.account_status = AccountStatus.SUSPENDED
    db_session.commit()

    res = client.post(
        "/api/v1/auth/login",
        json={"email": random_email, "password": password},
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert res.json()["detail"] == "Invalid email or password."


def test_login_disabled_account_rejected(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify disabled accounts cannot log in and receive generic error."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"email": random_email, "password": password},
    )
    user_id = reg_res.json()["id"]

    # Disable user
    user = db_session.get(User, user_id)
    user.account_status = AccountStatus.DISABLED
    db_session.commit()

    res = client.post(
        "/api/v1/auth/login",
        json={"email": random_email, "password": password},
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert res.json()["detail"] == "Invalid email or password."


def test_login_rate_limiting(client: TestClient):
    """Verify exceeding rate limit on login endpoint returns HTTP 429 with Retry-After header."""
    from app.core.rate_limit import limiter

    limiter.reset()
    try:
        limit = settings.RATE_LIMIT_LOGIN_PER_MINUTE
        # Exhaust the limit
        for _ in range(limit):
            res = client.post(
                "/api/v1/auth/login",
                json={"email": "attempt@example.com", "password": "WrongPassword1!"},
            )
            assert res.status_code == status.HTTP_401_UNAUTHORIZED

        # Next request must be 429
        rate_limited_res = client.post(
            "/api/v1/auth/login",
            json={"email": "attempt@example.com", "password": "WrongPassword1!"},
        )
        assert rate_limited_res.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Too many login attempts" in rate_limited_res.json()["detail"]
        assert "Retry-After" in rate_limited_res.headers
    finally:
        limiter.reset()
