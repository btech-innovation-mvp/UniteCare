"""Tests for logout, logout-all across multiple devices, and authenticated password changes."""

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def test_logout_revokes_current_session(client: TestClient, db_session: Session, random_email: str):
    """Verify POST /api/v1/auth/logout revokes the current session and renders the access token unusable."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]
    refresh_token = login_res.json()["refresh_token"]

    # Verify access works before logout
    me_before = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_before.status_code == status.HTTP_200_OK

    # Logout
    logout_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == status.HTTP_204_NO_CONTENT

    # Access token must now be rejected
    me_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_after.status_code == status.HTTP_401_UNAUTHORIZED

    # Refresh token rotation must also be rejected
    refresh_after = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_after.status_code == status.HTTP_401_UNAUTHORIZED


def test_logout_all_revokes_multiple_device_sessions(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify logout-all terminates all active sessions across multiple devices."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})

    # Device 1 login (e.g. desktop web)
    dev1_res = client.post(
        "/api/v1/auth/login",
        json={"email": random_email, "password": password},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    token1 = dev1_res.json()["access_token"]

    # Device 2 login (e.g. mobile app)
    dev2_res = client.post(
        "/api/v1/auth/login",
        json={"email": random_email, "password": password},
        headers={"User-Agent": "UniteCareMobile/1.0.0 (Android)"},
    )
    token2 = dev2_res.json()["access_token"]

    # Both tokens work initially
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code
        == 200
    )
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code
        == 200
    )

    # Execute logout-all from Device 1
    logout_all_res = client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {token1}"}
    )
    assert logout_all_res.status_code == status.HTTP_204_NO_CONTENT

    # Both sessions must now be rejected
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code
        == 401
    )
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code
        == 401
    )


def test_change_password_success(client: TestClient, db_session: Session, random_email: str):
    """Verify successful password change updates hash, invalidates sessions, and enforces new password."""
    old_password = "OldPassword123!"
    new_password = "NewStrongPassword456!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": old_password})

    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": old_password}
    )
    token = login_res.json()["access_token"]

    change_res = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": old_password, "new_password": new_password},
    )
    assert change_res.status_code == status.HTTP_200_OK

    # Existing session must now be invalidated
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )

    # Login with old password must fail
    fail_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": old_password}
    )
    assert fail_res.status_code == status.HTTP_401_UNAUTHORIZED

    # Login with new password must succeed
    succ_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": new_password}
    )
    assert succ_res.status_code == status.HTTP_200_OK


def test_change_password_wrong_current_password(client: TestClient, random_email: str):
    """Verify password change fails if current password does not match."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    change_res = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "WrongCurrentPassword!", "new_password": "NewPassword123!"},
    )
    assert change_res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect" in change_res.json()["detail"].lower()


def test_change_password_validation_rejection(client: TestClient, random_email: str):
    """Verify new password validation rejects short or oversized passwords."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    # Short password
    short_res = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": password, "new_password": "short"},
    )
    assert short_res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Oversized password > 72 bytes
    long_res = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": password, "new_password": "N" * 73},
    )
    assert long_res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
