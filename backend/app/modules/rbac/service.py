"""Role-Based Access Control (RBAC) service for roles, permissions, and assignment.

Architecture Principles:
- Authentication != Authorization
- User != Role
- Authorization is permission-based, not role-based.
- Roles are collections of permissions.
- Endpoints verify required permissions, avoiding scattered 'if user.role == ...' checks.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.audit.models import SecurityEventType
from app.modules.audit.service import log_security_event
from app.modules.rbac.models import Permission, Role, RolePermission, UserRole
from app.modules.users.models import User

# Standard system role and permission constants for Stage 3
PUBLIC_USER_ROLE = "public_user"

STANDARD_PERMISSIONS = [
    ("users:read", "Read user profile and account details"),
    ("users:manage", "Administrative management of user accounts and roles"),
    ("ngos:read", "Read registered NGO profiles"),
    ("ngos:manage", "Manage and verify NGO organizations"),
]


def ensure_system_rbac_seeds(db: Session) -> Role:
    """Ensure baseline system roles and permissions exist in database.

    This implements the system configuration record requirement.
    It does NOT create fake users.

    Returns:
        The baseline public_user Role entity.
    """
    # 1. Ensure permissions exist
    permissions_by_name: dict[str, Permission] = {}
    for name, description in STANDARD_PERMISSIONS:
        perm = db.execute(select(Permission).where(Permission.name == name)).scalar_one_or_none()
        if perm is None:
            perm = Permission(name=name, description=description)
            db.add(perm)
            db.flush()
        permissions_by_name[name] = perm

    # 2. Ensure public_user role exists
    public_role = db.execute(select(Role).where(Role.name == PUBLIC_USER_ROLE)).scalar_one_or_none()
    if public_role is None:
        public_role = Role(
            name=PUBLIC_USER_ROLE,
            description="Default standard role assigned upon registration",
        )
        db.add(public_role)
        db.flush()

    # 3. Enforce least privilege: public_user must NOT hold directory-level users:read or users:manage permissions.
    # Reading one's own profile (/api/v1/auth/me) requires only active authentication, not system-wide permissions.
    users_read_perm = permissions_by_name.get("users:read")
    if users_read_perm is not None:
        existing_link = db.execute(
            select(RolePermission).where(
                RolePermission.role_id == public_role.id,
                RolePermission.permission_id == users_read_perm.id,
            )
        ).scalar_one_or_none()
        if existing_link is not None:
            db.delete(existing_link)
            db.flush()

    return public_role


def assign_role_to_user(
    db: Session,
    user_id: uuid.UUID,
    role_name: str,
    assigned_by: uuid.UUID | None = None,
) -> UserRole:
    """Assign a role to a user and log a security audit event.

    Args:
        db: Database session.
        user_id: ID of the user receiving the role.
        role_name: Name of the role to assign.
        assigned_by: Optional ID of the user performing the assignment.

    Returns:
        The UserRole association entity.

    Raises:
        ValueError: If the user or role does not exist.
    """
    user = db.get(User, user_id)
    if user is None:
        raise ValueError(f"User {user_id} not found.")

    role = db.execute(select(Role).where(Role.name == role_name)).scalar_one_or_none()
    if role is None:
        raise ValueError(f"Role '{role_name}' not found.")

    existing = db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role.id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    user_role = UserRole(
        user_id=user_id,
        role_id=role.id,
        assigned_by=assigned_by,
    )
    db.add(user_role)
    db.flush()

    log_security_event(
        db,
        event_type=SecurityEventType.ROLE_ASSIGNED,
        user_id=user_id,
        metadata={"role": role_name, "assigned_by": str(assigned_by) if assigned_by else None},
    )
    return user_role


def remove_role_from_user(
    db: Session,
    user_id: uuid.UUID,
    role_name: str,
) -> bool:
    """Remove an assigned role from a user and log a security audit event.

    Args:
        db: Database session.
        user_id: ID of the user.
        role_name: Name of the role to remove.

    Returns:
        True if the role was removed, False if the user did not have the role.
    """
    role = db.execute(select(Role).where(Role.name == role_name)).scalar_one_or_none()
    if role is None:
        return False

    user_role = db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role.id,
        )
    ).scalar_one_or_none()
    if user_role is None:
        return False

    db.delete(user_role)
    db.flush()

    log_security_event(
        db,
        event_type=SecurityEventType.ROLE_REMOVED,
        user_id=user_id,
        metadata={"role": role_name},
    )
    return True


def get_user_permissions(db: Session, user_id: uuid.UUID) -> set[str]:
    """Resolve the complete set of distinct permissions granted to a user across all active roles.

    Queries:
        users -> user_roles -> roles -> role_permissions -> permissions

    Args:
        db: Database session.
        user_id: ID of the user.

    Returns:
        Set of permission name strings.
    """
    stmt = (
        select(Permission.name)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    results = db.execute(stmt).scalars().all()
    return set(results)


def user_has_permission(db: Session, user_id: uuid.UUID, permission_name: str) -> bool:
    """Check whether a user possesses a specific permission.

    Args:
        db: Database session.
        user_id: ID of the user.
        permission_name: Required permission name string (e.g. 'users:read').

    Returns:
        True if the user possesses the permission, False otherwise.
    """
    permissions = get_user_permissions(db, user_id)
    return permission_name in permissions
