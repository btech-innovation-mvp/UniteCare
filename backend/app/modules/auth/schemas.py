"""Pydantic schemas for authentication requests, responses, and token payloads."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from app.core.security import BCRYPT_MAX_BYTES
from app.modules.users.models import AccountStatus


class RegisterRequest(BaseModel):
    """Payload for user account registration."""

    email: EmailStr
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Strip whitespace and lowercase canonical email address."""
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, v: str) -> str:
        """Enforce password length and the architectural bcrypt 72-byte UTF-8 limit without silent truncation."""
        if not v or len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        byte_len = len(v.encode("utf-8"))
        if byte_len > BCRYPT_MAX_BYTES:
            raise ValueError(
                f"Password exceeds maximum length of {BCRYPT_MAX_BYTES} UTF-8 bytes "
                f"({byte_len} bytes received). Truncation is rejected."
            )
        return v


class LoginRequest(BaseModel):
    """Payload for credentials-based authentication."""

    email: EmailStr
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Strip whitespace and lowercase canonical email address."""
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, v: str) -> str:
        """Validate candidate password does not exceed bcrypt byte limits."""
        if not v:
            raise ValueError("Password cannot be empty.")
        byte_len = len(v.encode("utf-8"))
        if byte_len > BCRYPT_MAX_BYTES:
            raise ValueError(f"Password exceeds maximum limit of {BCRYPT_MAX_BYTES} bytes.")
        return v


class TokenResponse(BaseModel):
    """Successful authentication response with short-lived access JWT and opaque refresh token."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str


class RefreshRequest(BaseModel):
    """Payload for refresh-token rotation request."""

    refresh_token: str


class ChangePasswordRequest(BaseModel):
    """Payload for authenticated password change."""

    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password_bytes(cls, v: str) -> str:
        """Enforce length and bcrypt 72-byte limit on new password."""
        if not v or len(v) < 8:
            raise ValueError("New password must be at least 8 characters long.")
        byte_len = len(v.encode("utf-8"))
        if byte_len > BCRYPT_MAX_BYTES:
            raise ValueError(
                f"New password exceeds maximum length of {BCRYPT_MAX_BYTES} UTF-8 bytes "
                f"({byte_len} bytes received)."
            )
        return v


class UserResponse(BaseModel):
    """Safe user profile representation exposing no credentials or internal security secrets."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    account_status: AccountStatus
    created_at: datetime
    updated_at: datetime
