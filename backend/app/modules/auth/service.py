"""Authentication service managing registration, login, session lifecycle, and token rotation.

Core Security Invariants:
- Case-insensitive email uniqueness with transactional IntegrityError rollback.
- Direct bcrypt hashing with 72-byte UTF-8 limit.
- Opaque high-entropy refresh tokens with SHA-256 database hashing.
- Hierarchical lock ordering (UserSession -> RefreshToken) eliminating deadlock.
- Refresh token reuse detection revoking the entire token family and associated session.
- Generic authentication failure messaging preventing account enumeration.
- Append-only security audit event logging for all key lifecycle events.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationFailedException,
    EmailAlreadyExistsException,
)
from app.core.security import (
    create_access_token,
    generate_raw_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.modules.audit.models import SecurityEventType
from app.modules.audit.service import clean_ip_address, log_security_event
from app.modules.auth.models import AuthIdentity, RefreshToken, SessionStatus
from app.modules.auth.models import Session as UserSession
from app.modules.rbac.models import UserRole
from app.modules.rbac.service import ensure_system_rbac_seeds
from app.modules.users.models import AccountStatus, User


def register_user(
    db: Session,
    email: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> User:
    """Register a new user account with local credentials and assign public_user role.

    Transactional writes ensure atomicity across User, AuthIdentity, UserRole, and SecurityEvent.
    Catches IntegrityError on concurrent duplicate registrations to return clean 409 Conflict.
    """
    normalized_email = email.strip().lower()

    # 1. Enforce case-insensitive email uniqueness check
    existing_user = db.execute(
        select(User).where(func.lower(User.email) == normalized_email)
    ).scalar_one_or_none()
    if existing_user is not None:
        raise EmailAlreadyExistsException("An account with this email address already exists.")

    # 2. Hash password with bcrypt
    hashed_pwd = hash_password(password)

    try:
        # 3. Create user entity
        user = User(
            email=normalized_email,
            account_status=AccountStatus.ACTIVE,
        )
        db.add(user)
        db.flush()

        # 4. Create local authentication identity
        identity = AuthIdentity(
            user_id=user.id,
            provider="local",
            password_hash=hashed_pwd,
        )
        db.add(identity)
        db.flush()

        # 5. Ensure baseline system roles and permissions exist, then assign public_user role
        public_role = ensure_system_rbac_seeds(db)
        user_role = UserRole(
            user_id=user.id,
            role_id=public_role.id,
            assigned_by=None,  # System assigned
        )
        db.add(user_role)
        db.flush()

        # 6. Record security audit event
        log_security_event(
            db,
            event_type=SecurityEventType.ACCOUNT_REGISTERED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"email": normalized_email, "provider": "local"},
        )

        db.commit()
    except IntegrityError:
        db.rollback()
        raise EmailAlreadyExistsException("An account with this email address already exists.")

    db.refresh(user)
    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[User, UserSession, str, str]:
    """Authenticate a user using local credentials and issue access token and refresh token.

    Employs consistent generic authentication failure responses to prevent user/status enumeration.

    Returns:
        Tuple of (User, Session, access_token_str, raw_refresh_token_str).
    """
    normalized_email = email.strip().lower()

    # 1. Locate user
    user = db.execute(
        select(User).where(func.lower(User.email) == normalized_email)
    ).scalar_one_or_none()

    if user is None:
        log_security_event(
            db,
            event_type=SecurityEventType.LOGIN_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "user_not_found"},
        )
        db.commit()
        raise AuthenticationFailedException("Invalid email or password.")

    # 2. Check account status (generic failure response to avoid leaking account status)
    if user.account_status != AccountStatus.ACTIVE:
        log_security_event(
            db,
            event_type=SecurityEventType.LOGIN_FAILED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": f"account_{user.account_status.value.lower()}"},
        )
        db.commit()
        raise AuthenticationFailedException("Invalid email or password.")

    # 3. Locate local authentication identity
    identity = db.execute(
        select(AuthIdentity).where(
            AuthIdentity.user_id == user.id,
            AuthIdentity.provider == "local",
        )
    ).scalar_one_or_none()

    if identity is None or not identity.password_hash:
        log_security_event(
            db,
            event_type=SecurityEventType.LOGIN_FAILED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "no_local_identity"},
        )
        db.commit()
        raise AuthenticationFailedException("Invalid email or password.")

    # 4. Verify password
    if not verify_password(password, identity.password_hash):
        log_security_event(
            db,
            event_type=SecurityEventType.LOGIN_FAILED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "invalid_password"},
        )
        db.commit()
        raise AuthenticationFailedException("Invalid email or password.")

    # 5. Create persistent session
    now = datetime.now(UTC)
    session_expires_at = now + timedelta(days=settings.SESSION_EXPIRE_DAYS)
    cleaned_ip = clean_ip_address(ip_address)
    session = UserSession(
        user_id=user.id,
        status=SessionStatus.ACTIVE,
        ip_address=cleaned_ip,
        user_agent=user_agent,
        last_seen_at=now,
        expires_at=session_expires_at,
        created_at=now,
    )
    db.add(session)
    db.flush()

    # 6. Generate high-entropy opaque refresh token and store only its SHA-256 hash
    raw_refresh_token = generate_raw_refresh_token()
    token_hash = hash_refresh_token(raw_refresh_token)
    family_id = uuid.uuid4()
    refresh_expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    refresh_token = RefreshToken(
        session_id=session.id,
        token_hash=token_hash,
        family_id=family_id,
        issued_at=now,
        expires_at=refresh_expires_at,
    )
    db.add(refresh_token)
    db.flush()

    # 7. Record security audit events
    log_security_event(
        db,
        event_type=SecurityEventType.SESSION_CREATED,
        user_id=user.id,
        session_id=session.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    log_security_event(
        db,
        event_type=SecurityEventType.LOGIN_SUCCESS,
        user_id=user.id,
        session_id=session.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.commit()

    # 8. Issue short-lived access JWT
    access_token, _ = create_access_token(user.id, session.id)
    return user, session, access_token, raw_refresh_token


def rotate_refresh_token(
    db: Session,
    raw_token: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str, int]:
    """Rotate an opaque refresh token atomically with family reuse detection and hierarchical locking.

    Lock Acquisition Order:
        1. UserSession row (parent)
        2. RefreshToken row (child)
    This strictly prevents deadlock with concurrent logout operations.

    Returns:
        Tuple of (access_token_str, new_raw_refresh_token_str, expires_in_seconds).

    Raises:
        AuthenticationFailedException: If token is invalid, expired, revoked, or reuse is detected.
    """
    token_hash = hash_refresh_token(raw_token)
    now = datetime.now(UTC)

    # 1. Probe the token record's session_id without lock
    token_probe = db.execute(
        select(RefreshToken.session_id, RefreshToken.id).where(
            RefreshToken.token_hash == token_hash
        )
    ).first()

    if token_probe is None:
        raise AuthenticationFailedException("Invalid refresh token.")

    # 2. Acquire lock on parent UserSession FIRST (hierarchical lock ordering)
    session = db.execute(
        select(UserSession).where(UserSession.id == token_probe.session_id).with_for_update()
    ).scalar_one_or_none()

    if session is None:
        raise AuthenticationFailedException("Associated session is invalid, revoked, or expired.")

    # 3. Acquire lock on child RefreshToken SECOND
    token_record = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
    ).scalar_one_or_none()

    if token_record is None:
        raise AuthenticationFailedException("Invalid refresh token.")

    # 4. Check for token reuse (token was already used or revoked)
    if token_record.used_at is not None or token_record.revoked_at is not None:
        # TOKEN REUSE DETECTED! Invalidate entire family and session.
        db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == token_record.family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )

        session.status = SessionStatus.REVOKED

        log_security_event(
            db,
            event_type=SecurityEventType.REFRESH_TOKEN_REUSE_DETECTED,
            user_id=session.user_id,
            session_id=token_record.session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"family_id": str(token_record.family_id)},
        )
        db.commit()
        raise AuthenticationFailedException(
            "Refresh token reuse detected. All sessions in this chain have been revoked for security."
        )

    # 5. Check token expiration (persist revocation)
    if now > token_record.expires_at:
        token_record.revoked_at = now
        db.commit()
        raise AuthenticationFailedException("Refresh token has expired.")

    # 6. Check session status and expiration (persist EXPIRED state if past expires_at)
    if session.status != SessionStatus.ACTIVE:
        token_record.revoked_at = now
        db.commit()
        raise AuthenticationFailedException("Associated session is invalid, revoked, or expired.")

    if session.expires_at < now:
        session.status = SessionStatus.EXPIRED
        token_record.revoked_at = now
        db.commit()
        raise AuthenticationFailedException("Associated session is invalid, revoked, or expired.")

    # 7. Check user account status
    user = db.get(User, session.user_id)
    if user is None or user.account_status != AccountStatus.ACTIVE:
        token_record.revoked_at = now
        db.commit()
        raise AuthenticationFailedException("Account is inactive, suspended, or disabled.")

    # 8. Perform atomic rotation: consume current token
    token_record.used_at = now
    session.last_seen_at = now
    cleaned_ip = clean_ip_address(ip_address)
    if cleaned_ip:
        session.ip_address = cleaned_ip
    if user_agent:
        session.user_agent = user_agent

    # 9. Generate next refresh token preserving the same family_id
    new_raw_token = generate_raw_refresh_token()
    new_token_hash = hash_refresh_token(new_raw_token)
    new_refresh_record = RefreshToken(
        session_id=session.id,
        token_hash=new_token_hash,
        family_id=token_record.family_id,  # Same family
        issued_at=now,
        expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_refresh_record)
    db.flush()

    # 10. Record rotation audit event
    log_security_event(
        db,
        event_type=SecurityEventType.REFRESH_TOKEN_ROTATED,
        user_id=user.id,
        session_id=session.id,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata={"family_id": str(token_record.family_id)},
    )

    db.commit()

    # 11. Issue new access token
    access_token, _ = create_access_token(user.id, session.id)
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return access_token, new_raw_token, expires_in


def revoke_session(db: Session, session_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Revoke an active session and all its active refresh tokens using hierarchical locking."""
    now = datetime.now(UTC)

    # 1. Lock UserSession FIRST
    session = db.execute(
        select(UserSession)
        .where(UserSession.id == session_id, UserSession.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()

    if session:
        session.status = SessionStatus.REVOKED

        # 2. Invalidate active refresh tokens for this session SECOND
        db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id == session.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )

        log_security_event(
            db,
            event_type=SecurityEventType.SESSION_REVOKED,
            user_id=user_id,
            session_id=session_id,
        )
        db.commit()


def revoke_all_user_sessions(db: Session, user_id: uuid.UUID, commit: bool = True) -> None:
    """Revoke all active sessions and refresh-token chains for a user.

    Args:
        db: Database session.
        user_id: ID of user whose sessions are being revoked.
        commit: Whether to commit immediately. Set to False when called within a composite transaction.
    """
    now = datetime.now(UTC)

    # Lock all active sessions ordered by ID to eliminate deadlock across multi-session updates
    sessions = (
        db.execute(
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.status == SessionStatus.ACTIVE,
            )
            .order_by(UserSession.id)
            .with_for_update()
        )
        .scalars()
        .all()
    )

    for s in sessions:
        s.status = SessionStatus.REVOKED
        db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id == s.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        log_security_event(
            db,
            event_type=SecurityEventType.SESSION_REVOKED,
            user_id=user_id,
            session_id=s.id,
            metadata={"revocation_scope": "all_sessions"},
        )

    if commit:
        db.commit()


def change_user_password(
    db: Session,
    user_id: uuid.UUID,
    current_password: str,
    new_password: str,
) -> None:
    """Change a user's password in a single atomic transaction.

    Atomically:
    1. Updates password hash.
    2. Revokes all active sessions and refresh tokens.
    3. Logs PASSWORD_CHANGED security event.
    4. Commits as a single atomic unit of work.
    """
    identity = db.execute(
        select(AuthIdentity).where(
            AuthIdentity.user_id == user_id,
            AuthIdentity.provider == "local",
        )
    ).scalar_one_or_none()

    if identity is None or not identity.password_hash:
        raise AuthenticationFailedException("Local credentials not found for this user.")

    # Verify current password
    if not verify_password(current_password, identity.password_hash):
        raise AuthenticationFailedException("Current password is incorrect.")

    # Hash new password
    new_hash = hash_password(new_password)
    identity.password_hash = new_hash

    # Revoke all active sessions without committing yet
    revoke_all_user_sessions(db, user_id, commit=False)

    # Record security audit event
    log_security_event(
        db,
        event_type=SecurityEventType.PASSWORD_CHANGED,
        user_id=user_id,
    )

    # Single atomic commit for password update, session revocations, and audit event
    db.commit()
