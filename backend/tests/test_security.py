"""Unit tests for password security primitives."""

import pytest

from app.core.security import BCRYPT_MAX_BYTES, hash_password, verify_password


def test_hash_and_verify_valid_password():
    """Verify standard valid password hashing and verification."""
    plain = "CorrectHorseBatteryStaple!2026"
    hashed = hash_password(plain)

    assert hashed != plain
    assert hashed.startswith("$2b$12$")
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword!2026", hashed) is False


def test_empty_password_rejected():
    """Verify empty passwords raise ValueError on hash and return False on verify."""
    with pytest.raises(ValueError, match="Password cannot be empty"):
        hash_password("")

    assert verify_password("", "$2b$12$e8Yk2...") is False


def test_non_string_password_rejected():
    """Verify non-string inputs raise TypeError on hash and return False on verify."""
    with pytest.raises(TypeError, match="Password must be a string"):
        hash_password(None)  # type: ignore

    with pytest.raises(TypeError, match="Password must be a string"):
        hash_password(12345678)  # type: ignore

    assert verify_password(None, "hash") is False  # type: ignore
    assert verify_password("pass", None) is False  # type: ignore


def test_malformed_hash_returns_false_safely():
    """Verify malformed hash string does not cause unhandled crashes."""
    assert verify_password("password123", "not_a_valid_bcrypt_hash") is False
    assert verify_password("password123", "$invalid$format$hash") is False


def test_unicode_passwords():
    """Verify multi-byte Unicode strings (emojis, non-ASCII) hash and verify correctly."""
    unicode_passwords = [
        "UniteCare🔑Safe2026!🛡️",
        "MotDePasseSécurisé_Élégant!42",
        "БезопасныйПароль2026!✓",
        "安全なパスワード2026!★",
    ]
    for pwd in unicode_passwords:
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True
        assert verify_password(pwd + "x", hashed) is False


def test_exact_72_byte_limit():
    """Verify exactly 72 bytes UTF-8 password hashes and verifies successfully."""
    # 72 single-byte ASCII characters
    password_72_bytes = "A" * BCRYPT_MAX_BYTES
    assert len(password_72_bytes.encode("utf-8")) == 72

    hashed = hash_password(password_72_bytes)
    assert verify_password(password_72_bytes, hashed) is True


def test_unicode_72_byte_boundary():
    """Verify multi-byte Unicode characters accurately count towards 72 bytes."""
    # '€' is 3 bytes in UTF-8. 24 * 3 = 72 bytes.
    euro_24 = "€" * 24
    assert len(euro_24) == 24
    assert len(euro_24.encode("utf-8")) == 72

    hashed = hash_password(euro_24)
    assert verify_password(euro_24, hashed) is True

    # 25 * 3 = 75 bytes -> exceeds 72 bytes
    euro_25 = "€" * 25
    assert len(euro_25.encode("utf-8")) == 75

    with pytest.raises(ValueError, match="Password exceeds bcrypt maximum limit of 72 bytes"):
        hash_password(euro_25)

    assert verify_password(euro_25, hashed) is False


def test_oversized_password_rejected_explicitly():
    """Verify passwords over 72 bytes are rejected with clear error without silent truncation."""
    oversized = "B" * 73
    assert len(oversized.encode("utf-8")) == 73

    with pytest.raises(ValueError, match="Password exceeds bcrypt maximum limit of 72 bytes"):
        hash_password(oversized)

    assert verify_password(oversized, "$2b$12$somevalidhashstructuremockplaceholder...") is False
