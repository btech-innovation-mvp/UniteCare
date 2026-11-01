"""Tests for JWT access token verification pipeline and server-side session checks."""

import uuid
from datetime import timedelta

import jwt
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token
from app.modules.auth.models import Session as UserSession
from app.modules.auth.models import SessionStatus
from app.modules.users.models import AccountStatus, User


def test_valid_access_token_me_endpoint(client: TestClient, random_email: str):
    """Verify valid JWT access token provides authorized access to /api/v1/auth/me."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["email"] == random_email.lower()
    assert data["account_status"] == "ACTIVE"


def test_missing_authorization_header(client: TestClient):
    """Verify protected endpoints reject requests missing the Authorization header."""
    res = client.get("/api/v1/auth/me")
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_expired_access_token_rejected(client: TestClient, db_session: Session, random_email: str):
    """Verify expired JWT access tokens are rejected with 401."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    # Create token expired 10 minutes ago
    expired_token, _ = create_access_token(
        user_id=payload["sub"],
        session_id=payload["sid"],
        expires_delta=timedelta(minutes=-10),
    )

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid or expired" in res.json()["detail"].lower()


def test_invalid_signature_rejected(client: TestClient, random_email: str):
    """Verify tokens signed with an invalid key are rejected."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    valid_token = login_res.json()["access_token"]
    payload = jwt.decode(valid_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

    fake_token = jwt.encode(payload, "wrong_secret_key_12345678901234567890", algorithm="HS256")
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {fake_token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_revoked_session_rejects_access_token(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify server-side session check prevents access even if JWT signature is valid."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

    # Revoke session in database
    session = db_session.get(UserSession, payload["sid"])
    session.status = SessionStatus.REVOKED
    db_session.commit()

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "revoked" in res.json()["detail"].lower()


def test_suspended_user_rejects_access_token(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify access token is rejected if user account is subsequently suspended."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register", json={"email": random_email, "password": password}
    )
    user_id = reg_res.json()["id"]

    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    # Suspend user
    user = db_session.get(User, user_id)
    user.account_status = AccountStatus.SUSPENDED
    db_session.commit()

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "suspended" in res.json()["detail"].lower() or "inactive" in res.json()["detail"].lower()


def test_nonexistent_session_id_rejected(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify access token containing a non-existent session ID is rejected."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register", json={"email": random_email, "password": password}
    )
    user_id = reg_res.json()["id"]

    orphan_token, _ = create_access_token(user_id=user_id, session_id=uuid.uuid4())
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {orphan_token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
