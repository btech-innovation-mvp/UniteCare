"""FastAPI dependency injection utilities for authentication, sessions, and RBAC permissions."""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AccountInactiveException,
    AuthenticationFailedException,
    PermissionDeniedException,
)
from app.core.security import decode_access_token
from app.db.session import get_db
from app.modules.auth.models import Session as UserSession
from app.modules.auth.models import SessionStatus
from app.modules.rbac.service import user_has_permission
from app.modules.users.models import AccountStatus, User

# HTTP Bearer authentication scheme
bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    """Authenticated context carrying validated User and Session entities."""

    user: User
    session: UserSession


def get_current_auth_context(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> AuthContext:
    """Validate JWT access token and verify server-side user and session status.

    Pipeline:
    1. Extract access token
    2. Verify JWT signature & expiration
    3. Identify user & check account status
    4. Identify session from sid & check session status
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationFailedException("Authentication credentials missing.")

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise AuthenticationFailedException("Invalid or expired access token.")

    try:
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
    except (KeyError, ValueError):
        raise AuthenticationFailedException("Malformed token claims.")

    # 1. Server-side user identity and status verification
    user = db.get(User, user_id)
    if user is None:
        raise AuthenticationFailedException("User not found.")

    if user.account_status != AccountStatus.ACTIVE:
        raise AccountInactiveException("Account is suspended or disabled.")

    # 2. Server-side session verification
    session = db.get(UserSession, session_id)
    if session is None or session.user_id != user.id:
        raise AuthenticationFailedException("Invalid session context.")

    now = datetime.now(UTC)
    if session.status != SessionStatus.ACTIVE:
        raise AuthenticationFailedException("Session has been revoked or expired.")

    if session.expires_at < now:
        session.status = SessionStatus.EXPIRED
        db.commit()
        raise AuthenticationFailedException("Session has been revoked or expired.")

    # Throttled session activity update: update last_seen_at only if >= 60 seconds elapsed
    if (now - session.last_seen_at).total_seconds() >= 60:
        session.last_seen_at = now
        db.flush()

    return AuthContext(user=user, session=session)


def get_current_user(
    auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
) -> User:
    """Dependency that extracts the active authenticated User entity."""
    return auth_ctx.user


def get_current_session(
    auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
) -> UserSession:
    """Dependency that extracts the active authenticated Session entity."""
    return auth_ctx.session


def require_permission(permission_name: str) -> Callable:
    """Factory dependency enforcing a specific granular permission on an authenticated endpoint.

    Architecture Rule:
    - Authorization is permission-based, not role-based.
    - Resolves permissions dynamically from user's assigned roles in PostgreSQL.
    """

    def _permission_dependency(
        auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
        db: Annotated[Session, Depends(get_db)],
    ) -> AuthContext:
        if not user_has_permission(db, auth_ctx.user.id, permission_name):
            raise PermissionDeniedException(
                f"Action forbidden: missing required permission '{permission_name}'."
            )
        return auth_ctx

    return _permission_dependency
