"""Tests for refresh-token rotation, family reuse detection, and session invalidation."""

from datetime import UTC, datetime, timedelta

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_refresh_token
from app.modules.audit.models import SecurityEvent, SecurityEventType
from app.modules.auth.models import RefreshToken, SessionStatus
from app.modules.auth.models import Session as UserSession


def test_successful_refresh_token_rotation(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify refresh token rotation consumes the old token, issues a new one with same family_id, and issues new JWT."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    initial_rt = login_res.json()["refresh_token"]

    initial_hash = hash_refresh_token(initial_rt)
    initial_record = db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == initial_hash)
    ).scalar_one()
    initial_family_id = initial_record.family_id

    # Rotate
    refresh_res = client.post("/api/v1/auth/refresh", json={"refresh_token": initial_rt})
    assert refresh_res.status_code == status.HTTP_200_OK
    new_data = refresh_res.json()
    assert "access_token" in new_data
    assert "refresh_token" in new_data
    assert new_data["refresh_token"] != initial_rt

    # Check database: initial token must now have used_at timestamp
    db_session.refresh(initial_record)
    assert initial_record.used_at is not None

    # Check new token in DB: must inherit the exact same family_id
    new_hash = hash_refresh_token(new_data["refresh_token"])
    new_record = db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == new_hash)
    ).scalar_one()
    assert new_record.family_id == initial_family_id
    assert new_record.used_at is None
    assert new_record.revoked_at is None


def test_refresh_token_reuse_detection_and_family_revocation(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify presenting an already-used refresh token revokes the entire family and the associated session."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    rt1 = login_res.json()["refresh_token"]

    # 1. Legitimate rotation: rt1 -> rt2
    rot1_res = client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})
    assert rot1_res.status_code == status.HTTP_200_OK
    rt2 = rot1_res.json()["refresh_token"]
    access_token2 = rot1_res.json()["access_token"]

    # 2. Token theft/reuse attempt: an attacker presents the already-used rt1!
    reuse_res = client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})
    assert reuse_res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "reuse detected" in reuse_res.json()["detail"].lower()

    # 3. Verify security response: the entire family and session must be revoked
    rt1_hash = hash_refresh_token(rt1)
    rt1_record = db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == rt1_hash)
    ).scalar_one()
    session = db_session.get(UserSession, rt1_record.session_id)
    assert session.status == SessionStatus.REVOKED

    # rt2 in the same family must also be revoked
    rt2_hash = hash_refresh_token(rt2)
    rt2_record = db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == rt2_hash)
    ).scalar_one()
    assert rt2_record.revoked_at is not None

    # Audit event logged
    event = db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.session_id == session.id,
            SecurityEvent.event_type == SecurityEventType.REFRESH_TOKEN_REUSE_DETECTED.value,
        )
    ).scalar_one_or_none()
    assert event is not None

    # Subsequent access with access_token2 should also fail because the session was revoked
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token2}"})
    assert me_res.status_code == status.HTTP_401_UNAUTHORIZED

    # Trying to use rt2 now must also fail
    rot2_res = client.post("/api/v1/auth/refresh", json={"refresh_token": rt2})
    assert rot2_res.status_code == status.HTTP_401_UNAUTHORIZED


def test_expired_refresh_token_rejected(client: TestClient, db_session: Session, random_email: str):
    """Verify expired refresh tokens cannot be rotated."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    rt = login_res.json()["refresh_token"]

    # Manually expire the token in DB
    rt_hash = hash_refresh_token(rt)
    record = db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == rt_hash)
    ).scalar_one()
    record.expires_at = datetime.now(UTC) - timedelta(days=1)
    db_session.commit()

    res = client.post("/api/v1/auth/refresh", json={"refresh_token": rt})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "expired" in res.json()["detail"].lower()


def test_unknown_refresh_token_rejected(client: TestClient):
    """Verify arbitrary unknown refresh tokens are rejected."""
    res = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": "nonexistent_fake_refresh_token"}
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
