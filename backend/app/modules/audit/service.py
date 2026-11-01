"""Security event audit logging service.

Critical Constraints:
- Security events are strictly append-only.
- Never persist passwords, password hashes, raw tokens, or secrets into metadata.
- Uses controlled event vocabulary from SecurityEventType.
"""

import re
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.modules.audit.models import SecurityEvent, SecurityEventType

# Forbidden sensitive metadata substrings and keywords that must never be persisted
SENSITIVE_KEY_SUBSTRINGS = {
    "password",
    "password_hash",
    "passwd",
    "secret",
    "token",
    "jwt",
    "key",
    "auth",
    "cookie",
    "credential",
    "bearer",
    "private",
    "database_url",
}

# Regex patterns for detecting embedded credentials, headers, and tokens in longer strings
JWT_PATTERN = re.compile(r"ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")
BEARER_PATTERN = re.compile(r"bearer[\s:]+\S+", re.IGNORECASE)
AUTHORIZATION_PATTERN = re.compile(r"authorization\s*[:=]\s*\S+", re.IGNORECASE)
BASIC_AUTH_PATTERN = re.compile(r"basic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)

EMBEDDED_SENSITIVE_ASSIGNMENTS = (
    "password=",
    "password:",
    "passwd=",
    "passwd:",
    "secret=",
    "secret:",
    "token=",
    "token:",
    "access_token=",
    "access_token:",
    "refresh_token=",
    "refresh_token:",
    "session=",
    "session:",
    "jwt=",
    "jwt:",
    "api_key=",
    "api_key:",
    "apikey=",
    "apikey:",
    "private_key=",
    "private_key:",
)


def _is_sensitive_key(key: str) -> bool:
    """Check whether a metadata key contains sensitive substrings."""
    key_lower = str(key).lower()
    return any(sub in key_lower for sub in SENSITIVE_KEY_SUBSTRINGS)


def _sanitize_value(key: str, value: Any) -> Any:
    """Recursively sanitize metadata values across dicts, lists, primitives, and headers."""
    if _is_sensitive_key(key):
        return "[REDACTED]"

    if isinstance(value, dict):
        return {str(k): _sanitize_value(str(k), v) for k, v in value.items()}
    elif isinstance(value, (list, tuple, set)):
        return [_sanitize_value(key, item) for item in value]
    elif isinstance(value, str):
        v_lower = value.strip().lower()

        # 1. Redact Authorization headers, Bearer tokens, or Basic credentials embedded anywhere
        if (
            BEARER_PATTERN.search(value)
            or AUTHORIZATION_PATTERN.search(value)
            or BASIC_AUTH_PATTERN.search(value)
        ):
            return "[REDACTED]"

        # 2. Redact compact JWT patterns embedded anywhere in the string
        if JWT_PATTERN.search(value):
            return "[REDACTED]"

        # 3. Redact embedded sensitive token/secret assignments (query params, cookies, key-value pairs)
        if any(pattern in v_lower for pattern in EMBEDDED_SENSITIVE_ASSIGNMENTS):
            return "[REDACTED]"

        return value
    else:
        return value


def _sanitize_metadata(data: dict[str, Any] | None) -> dict[str, Any]:
    """Recursively sanitize metadata dictionary to prevent leaking sensitive information."""
    if not data or not isinstance(data, dict):
        return {}
    return {str(k): _sanitize_value(str(k), v) for k, v in data.items()}


def clean_ip_address(ip: str | None) -> str | None:
    """Validate and format IP address string ensuring compatibility with PostgreSQL INET type."""
    if not ip:
        return None
    ip_str = ip.strip()
    if ip_str in ("testclient", "localhost"):
        return "127.0.0.1"
    try:
        import ipaddress

        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        return None


def log_security_event(
    db: Session,
    event_type: str | SecurityEventType,
    user_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityEvent:
    """Record an append-only security audit event.

    Args:
        db: SQLAlchemy database session.
        event_type: Controlled event type string or enum.
        user_id: Optional ID of the user associated with the event.
        session_id: Optional ID of the session associated with the event.
        ip_address: Optional client IP address.
        user_agent: Optional client user agent string.
        metadata: Optional event-specific metadata dictionary.

    Returns:
        The newly created SecurityEvent record.
    """
    type_str = event_type.value if isinstance(event_type, SecurityEventType) else str(event_type)
    sanitized_metadata = _sanitize_metadata(metadata)
    cleaned_ip = clean_ip_address(ip_address)

    event = SecurityEvent(
        user_id=user_id,
        session_id=session_id,
        event_type=type_str,
        ip_address=cleaned_ip,
        user_agent=user_agent,
        metadata_=sanitized_metadata,
    )
    db.add(event)
    db.flush()
    return event
