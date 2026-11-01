"""Tests for security event audit logging service and sensitive data redaction."""

from sqlalchemy.orm import Session

from app.modules.audit.models import SecurityEvent, SecurityEventType
from app.modules.audit.service import log_security_event
from app.modules.users.models import User


def test_security_event_logging_and_redaction(db_session: Session, random_email: str):
    """Verify security event logging records controlled event types and redacts sensitive metadata keys."""
    user = User(email=random_email)
    db_session.add(user)
    db_session.commit()

    # Log an event containing potentially dangerous sensitive keys
    event = log_security_event(
        db=db_session,
        event_type=SecurityEventType.LOGIN_SUCCESS,
        user_id=user.id,
        ip_address="192.168.1.100",
        user_agent="TestClient/1.0",
        metadata={
            "device": "mobile",
            "password": "SecretPlaintextPassword123!",
            "raw_token": "high_entropy_secret_token",
            "safe_attribute": "safe_value",
            "nested": {
                "jwt_secret": "my_super_secret_jwt_key",
                "nested_safe": 42,
            },
        },
    )
    db_session.commit()

    saved_event = db_session.get(SecurityEvent, event.id)
    assert saved_event is not None
    assert saved_event.event_type == SecurityEventType.LOGIN_SUCCESS.value
    assert str(saved_event.ip_address) == "192.168.1.100"

    # Verify redactions
    meta = saved_event.metadata_
    assert meta["safe_attribute"] == "safe_value"
    assert meta["device"] == "mobile"
    assert meta["password"] == "[REDACTED]"
    assert meta["raw_token"] == "[REDACTED]"
    assert meta["nested"]["jwt_secret"] == "[REDACTED]"
    assert meta["nested"]["nested_safe"] == 42


def test_security_event_recursive_redaction_advanced(db_session: Session, random_email: str):
    """Verify recursive redaction handles lists of dicts, bearer headers, cookies, and tokens."""
    user = User(email=random_email)
    db_session.add(user)
    db_session.commit()

    complex_metadata = {
        "headers": [
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5",
            "Content-Type: application/json",
            "Safe-Header: 123",
        ],
        "untrusted_inputs": [
            "session=abc123secret",
            "refresh_token=super_secret_cookie_val",
            "analytics_id=anon123",
        ],
        "items": [
            {"name": "item1", "api_key": "private_secret_key"},
            {"name": "item2", "token": "sensitive_token_value"},
            {"name": "item3", "public_info": "visible"},
        ],
        "auth_header": "Bearer some-access-token-string",
        "authorization": "Basic dXNlcjpwYXNz",
        "cookies": ["cookie1=abc", "cookie2=xyz"],
        "client_metadata": {
            "app_version": "1.0.0",
            "secret_client_token": "hidden_string",
        },
    }

    event = log_security_event(
        db=db_session,
        event_type=SecurityEventType.LOGIN_FAILED,
        user_id=user.id,
        metadata=complex_metadata,
    )
    db_session.commit()

    saved_event = db_session.get(SecurityEvent, event.id)
    assert saved_event is not None
    meta = saved_event.metadata_

    # Check headers list (redacts Bearer tokens within list of strings)
    assert meta["headers"][0] == "[REDACTED]"
    assert meta["headers"][1] == "Content-Type: application/json"
    assert meta["headers"][2] == "Safe-Header: 123"

    # Check non-sensitive list containing cookie assignments (redacts session/refresh_token cookies)
    assert meta["untrusted_inputs"][0] == "[REDACTED]"
    assert meta["untrusted_inputs"][1] == "[REDACTED]"
    assert meta["untrusted_inputs"][2] == "analytics_id=anon123"

    # Check list of dicts (redacts sensitive keys within items)
    assert meta["items"][0]["api_key"] == "[REDACTED]"
    assert meta["items"][0]["name"] == "item1"
    assert meta["items"][1]["token"] == "[REDACTED]"
    assert meta["items"][1]["name"] == "item2"
    assert meta["items"][2]["public_info"] == "visible"

    # Check keys containing sensitive substrings (completely redacted at top level)
    assert meta["auth_header"] == "[REDACTED]"
    assert meta["authorization"] == "[REDACTED]"
    assert meta["cookies"] == "[REDACTED]"

    # Check nested dict within non-sensitive key
    assert meta["client_metadata"]["app_version"] == "1.0.0"
    assert meta["client_metadata"]["secret_client_token"] == "[REDACTED]"


def test_security_event_embedded_token_and_header_redaction(db_session: Session, random_email: str):
    """Regression test: verify authorization headers, JWTs, and credentials embedded in longer strings are redacted."""
    user = User(email=random_email)
    db_session.add(user)
    db_session.commit()

    embedded_metadata = {
        "client_log": "Client sent Authorization: Bearer secret_access_token_12345 in request",
        "error_detail": (
            "Failed authenticating bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5 with server"
        ),
        "token_debug": (
            "Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5 expired at 12:00"
        ),
        "redirect_target": "https://frontend.unitecare.org/callback?access_token=secret_val_abc&state=123",
        "cookie_trace": "Observed Cookie: session=session_id_val_99; refresh_token=super_secret_refresh",
        "auth_line": "Header authorization: Basic dXNlcjpwYXNzd29yZDEyMw==",
        "normal_message": "User completed profile verification",
        "attempt_count": 3,
        "is_retry": True,
    }

    event = log_security_event(
        db=db_session,
        event_type=SecurityEventType.LOGIN_FAILED,
        user_id=user.id,
        metadata=embedded_metadata,
    )
    db_session.commit()

    saved_event = db_session.get(SecurityEvent, event.id)
    assert saved_event is not None
    meta = saved_event.metadata_

    # Verify all strings containing embedded credentials or headers were safely redacted
    assert meta["client_log"] == "[REDACTED]"
    assert meta["error_detail"] == "[REDACTED]"
    assert meta["token_debug"] == "[REDACTED]"
    assert meta["redirect_target"] == "[REDACTED]"
    assert meta["cookie_trace"] == "[REDACTED]"
    assert meta["auth_line"] == "[REDACTED]"

    # Verify benign fields are untouched
    assert meta["normal_message"] == "User completed profile verification"
    assert meta["attempt_count"] == 3
    assert meta["is_retry"] is True


def test_controlled_security_event_types_coverage():
    """Verify that all minimum required event types exist in SecurityEventType enum."""
    required_events = {
        "ACCOUNT_REGISTERED",
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "SESSION_CREATED",
        "SESSION_REVOKED",
        "SESSION_EXPIRED",
        "REFRESH_TOKEN_ROTATED",
        "REFRESH_TOKEN_REUSE_DETECTED",
        "PASSWORD_CHANGED",
        "ACCOUNT_SUSPENDED",
        "ACCOUNT_DISABLED",
        "ACCOUNT_REACTIVATED",
        "ROLE_ASSIGNED",
        "ROLE_REMOVED",
    }
    actual_events = {e.value for e in SecurityEventType}
    assert required_events.issubset(actual_events)
