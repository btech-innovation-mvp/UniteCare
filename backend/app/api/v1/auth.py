"""Authentication API v1 endpoints for registration, login, token rotation, and session management."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_current_auth_context, get_current_user
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.modules.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.modules.auth.service import (
    authenticate_user,
    change_user_password,
    register_user,
    revoke_all_user_sessions,
    revoke_session,
    rotate_refresh_token,
)
from app.modules.users.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


def _extract_client_context(request: Request) -> tuple[str | None, str | None]:
    """Safely extract client IP address and User-Agent header."""
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return ip, user_agent


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(
    request: Request,
    payload: RegisterRequest,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Create a new user account with local credentials and default public_user role."""
    enforce_rate_limit(
        request, action="register", max_requests=settings.RATE_LIMIT_REGISTER_PER_MINUTE
    )
    ip, user_agent = _extract_client_context(request)
    user = register_user(
        db=db,
        email=payload.email,
        password=payload.password,
        ip_address=ip,
        user_agent=user_agent,
    )
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and issue access and refresh tokens",
)
def login(
    request: Request,
    payload: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    """Authenticate with email and password, establishing a persistent session."""
    enforce_rate_limit(request, action="login", max_requests=settings.RATE_LIMIT_LOGIN_PER_MINUTE)
    ip, user_agent = _extract_client_context(request)
    _, _, access_token, raw_refresh_token = authenticate_user(
        db=db,
        email=payload.email,
        password=payload.password,
        ip_address=ip,
        user_agent=user_agent,
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=raw_refresh_token,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and issue new access token",
)
def refresh(
    request: Request,
    payload: RefreshRequest,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    """Rotate an opaque refresh token with atomic concurrency locking and family reuse detection."""
    ip, user_agent = _extract_client_context(request)
    access_token, new_raw_refresh, expires_in = rotate_refresh_token(
        db=db,
        raw_token=payload.refresh_token,
        ip_address=ip,
        user_agent=user_agent,
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        refresh_token=new_raw_refresh,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the current session and active refresh tokens",
)
def logout(
    auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    """Revoke the calling device context session."""
    revoke_session(db=db, session_id=auth_ctx.session.id, user_id=auth_ctx.user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all active sessions and refresh-token chains for the user",
)
def logout_all(
    auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    """Revoke all sessions across all devices for the current user."""
    revoke_all_user_sessions(db=db, user_id=auth_ctx.user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    summary="Change password and invalidate all existing sessions",
)
def change_password(
    auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
    payload: ChangePasswordRequest,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    """Update password, update bcrypt hash, and revoke all existing sessions to enforce re-login."""
    change_user_password(
        db=db,
        user_id=auth_ctx.user.id,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    return {"message": "Password changed successfully. All previous sessions have been revoked."}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Return safe public identity details of the authenticated actor."""
    return current_user


@router.get(
    "/permissions",
    summary="Get permissions granted to the current authenticated user",
)
def get_my_permissions(
    auth_ctx: Annotated[AuthContext, Depends(get_current_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, list[str]]:
    """Return list of granular permissions resolved for current user."""
    from app.modules.rbac.service import get_user_permissions

    perms = get_user_permissions(db, auth_ctx.user.id)
    return {"permissions": sorted(perms)}
