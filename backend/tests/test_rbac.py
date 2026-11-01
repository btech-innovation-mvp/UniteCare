"""Tests for permission-based RBAC, role assignment, and endpoint authorization."""

import uuid

from fastapi import APIRouter, Depends, status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.main import app
from app.modules.rbac.models import Permission, Role, RolePermission
from app.modules.rbac.service import (
    assign_role_to_user,
    get_user_permissions,
    remove_role_from_user,
    user_has_permission,
)
from app.modules.users.models import User

# Test-only router for testing require_permission dependency without deploying demo endpoints to production
_test_rbac_router = APIRouter()


@_test_rbac_router.get(
    "/test-rbac-guard",
    dependencies=[Depends(require_permission("users:manage"))],
)
def _test_guard_endpoint():
    return {"message": "authorized with users:manage"}


@_test_rbac_router.get(
    "/test-rbac-users-read-guard",
    dependencies=[Depends(require_permission("users:read"))],
)
def _test_users_read_guard_endpoint():
    return {"message": "authorized with users:read"}


# Register test router on app
app.include_router(_test_rbac_router)


def test_public_user_baseline_permissions(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify registered public_user has no directory-level permissions (least privilege)."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    perm_res = client.get("/api/v1/auth/permissions", headers={"Authorization": f"Bearer {token}"})
    assert perm_res.status_code == status.HTTP_200_OK
    perms = perm_res.json()["permissions"]
    assert "users:read" not in perms
    assert "users:manage" not in perms
    assert perms == []

    # Verify public_user is forbidden from reading user directory
    read_res = client.get(
        "/test-rbac-users-read-guard", headers={"Authorization": f"Bearer {token}"}
    )
    assert read_res.status_code == status.HTTP_403_FORBIDDEN
    assert "missing required permission" in read_res.json()["detail"].lower()

    # Verify public_user is also forbidden from managing users
    manage_res = client.get("/test-rbac-guard", headers={"Authorization": f"Bearer {token}"})
    assert manage_res.status_code == status.HTTP_403_FORBIDDEN
    assert "missing required permission" in manage_res.json()["detail"].lower()



def test_permission_enforcement_forbidden_for_unauthorized_user(
    client: TestClient, random_email: str
):
    """Verify endpoint requiring users:manage returns 403 Forbidden for default public_user."""
    password = "CorrectPassword123!"
    client.post("/api/v1/auth/register", json={"email": random_email, "password": password})
    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    # Attempt accessing endpoint guarded by require_permission('users:manage')
    res = client.get("/test-rbac-guard", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_403_FORBIDDEN
    assert "forbidden" in res.json()["detail"].lower()


def test_permission_granted_via_role_assignment(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify granting a role with users:manage dynamically authorizes the user without role hardcoding."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register", json={"email": random_email, "password": password}
    )
    user_id = uuid.UUID(reg_res.json()["id"])

    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    # 1. Create a custom coordinator role that has users:manage permission
    manage_perm = db_session.execute(
        select(Permission).where(Permission.name == "users:manage")
    ).scalar_one()

    custom_role = Role(name=f"coordinator_{uuid.uuid4().hex[:6]}", description="Custom Coordinator")
    db_session.add(custom_role)
    db_session.flush()

    db_session.add(RolePermission(role_id=custom_role.id, permission_id=manage_perm.id))
    db_session.commit()

    # 2. Assign role to user
    assign_role_to_user(db_session, user_id=user_id, role_name=custom_role.name)
    db_session.commit()

    # 3. Access endpoint again: now succeeds with 200!
    res = client.get("/test-rbac-guard", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_200_OK
    assert "authorized" in res.json()["message"]


def test_role_removal_revokes_permission(
    client: TestClient, db_session: Session, random_email: str
):
    """Verify removing a role immediately revokes associated permissions."""
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register", json={"email": random_email, "password": password}
    )
    user_id = uuid.UUID(reg_res.json()["id"])

    login_res = client.post(
        "/api/v1/auth/login", json={"email": random_email, "password": password}
    )
    token = login_res.json()["access_token"]

    manage_perm = db_session.execute(
        select(Permission).where(Permission.name == "users:manage")
    ).scalar_one()
    role_name = f"manager_{uuid.uuid4().hex[:6]}"
    custom_role = Role(name=role_name)
    db_session.add(custom_role)
    db_session.flush()
    db_session.add(RolePermission(role_id=custom_role.id, permission_id=manage_perm.id))
    db_session.commit()

    # Assign
    assign_role_to_user(db_session, user_id=user_id, role_name=role_name)
    db_session.commit()
    assert (
        client.get("/test-rbac-guard", headers={"Authorization": f"Bearer {token}"}).status_code
        == 200
    )

    # Remove role
    removed = remove_role_from_user(db_session, user_id=user_id, role_name=role_name)
    assert removed is True
    db_session.commit()

    # Access is now forbidden
    assert (
        client.get("/test-rbac-guard", headers={"Authorization": f"Bearer {token}"}).status_code
        == 403
    )


def test_multiple_roles_permission_union(db_session: Session, random_email: str):
    """Verify multiple assigned roles merge all granted permissions without conflicts."""
    user = User(email=random_email)
    db_session.add(user)
    db_session.commit()

    # Role A has users:read
    role_a = Role(name=f"role_a_{uuid.uuid4().hex[:6]}")
    # Role B has users:manage
    role_b = Role(name=f"role_b_{uuid.uuid4().hex[:6]}")
    db_session.add_all([role_a, role_b])
    db_session.flush()

    p_read = db_session.execute(
        select(Permission).where(Permission.name == "users:read")
    ).scalar_one()
    p_manage = db_session.execute(
        select(Permission).where(Permission.name == "users:manage")
    ).scalar_one()

    db_session.add(RolePermission(role_id=role_a.id, permission_id=p_read.id))
    db_session.add(RolePermission(role_id=role_b.id, permission_id=p_manage.id))
    db_session.commit()

    assign_role_to_user(db_session, user.id, role_a.name)
    assign_role_to_user(db_session, user.id, role_b.name)
    db_session.commit()

    perms = get_user_permissions(db_session, user.id)
    assert "users:read" in perms
    assert "users:manage" in perms
    assert user_has_permission(db_session, user.id, "users:read") is True
    assert user_has_permission(db_session, user.id, "users:manage") is True
    assert user_has_permission(db_session, user.id, "nonexistent:perm") is False
