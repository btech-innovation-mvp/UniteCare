"""Cryptographic, password security, and JWT primitives for UniteCare.

Engineering Principles:
- Uses direct `bcrypt` library (version 5.0+).
- Enforces an explicit 72-byte UTF-8 password limit to prevent silent truncation.
- Bcrypt work factor configured via application settings.
- Sensitive values (passwords, salts, hashes, raw tokens) must never be logged.
- JWT access tokens contain minimal claims (sub, sid, jti, iat, exp).
- Refresh tokens are high-entropy opaque strings; only SHA-256 digests are stored in the database.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

# Bcrypt hard architectural limit of 72 bytes (UTF-8 encoded)
BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt.

    Args:
        password: Plaintext password string.

    Returns:
        Hashed password string (UTF-8 decoded).

    Raises:
        ValueError: If password is empty or exceeds 72 UTF-8 bytes.
        TypeError: If password is not a string.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    password_bytes = password.encode("utf-8")
    if len(password_bytes) > BCRYPT_MAX_BYTES:
        raise ValueError(
            f"Password exceeds bcrypt maximum limit of {BCRYPT_MAX_BYTES} bytes "
            f"({len(password_bytes)} UTF-8 bytes provided). Truncation is rejected."
        )

    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Safely handles invalid formats, malformed hashes, and oversized inputs
    without raising unhandled exceptions or leaking timing information.

    Args:
        password: Plaintext candidate password string.
        hashed_password: Stored bcrypt hash string.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    if not isinstance(password, str) or not isinstance(hashed_password, str):
        return False

    if not password or not hashed_password:
        return False

    password_bytes = password.encode("utf-8")
    # If the candidate exceeds 72 bytes, it cannot match a valid bcrypt hash
    if len(password_bytes) > BCRYPT_MAX_BYTES:
        return False

    try:
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except (ValueError, TypeError):
        # Malformed or unrecognized hash format
        return False


def create_access_token(
    user_id: uuid.UUID | str,
    session_id: uuid.UUID | str,
    expires_delta: timedelta | None = None,
) -> tuple[str, dict[str, Any]]:
    """Create a short-lived JWT access token with minimal claims.

    Claims:
        sub: user_id (string UUID)
        sid: session_id (string UUID)
        jti: unique token identifier (string UUID)
        iat: issued-at timestamp (int seconds)
        exp: expiration timestamp (int seconds)

    Args:
        user_id: User identifier.
        session_id: Session identifier.
        expires_delta: Optional custom lifetime override.

    Returns:
        Tuple of (encoded_jwt_string, claims_dict).
    """
    now = datetime.now(UTC)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    claims: dict[str, Any] = {
        "sub": str(user_id),
        "sid": str(session_id),
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    token = jwt.encode(
        claims,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token, claims


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Verifies signature, algorithm, expiration, and ensures required minimal claims exist.

    Args:
        token: Encoded JWT string.

    Returns:
        Dictionary of validated claims.

    Raises:
        jwt.PyJWTError: On invalid signature, expired token, or malformed claims.
    """
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "sid", "jti", "iat", "exp"]},
    )
    return payload


def generate_raw_refresh_token() -> str:
    """Generate a cryptographically secure, high-entropy opaque refresh token.

    Returns:
        URL-safe high-entropy random string (48 bytes entropy, ~64 chars).
    """
    return secrets.token_urlsafe(48)


def hash_refresh_token(raw_token: str) -> str:
    """Hash a raw refresh token using SHA-256 for persistent database storage.

    Never store raw refresh tokens in the database.

    Args:
        raw_token: Plaintext opaque refresh token.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
