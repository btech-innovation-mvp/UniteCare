"""Genuine PostgreSQL concurrency tests for token rotation, session revocation, and registration.

Verifies:
1. Concurrent refresh token rotation:
   - Two concurrent threads attempt to rotate the exact same refresh token.
   - Exactly one succeeds; the second detects reuse and revokes the session family.
   - Hierarchical lock ordering (UserSession -> RefreshToken) prevents deadlocks in PostgreSQL.
2. Concurrent refresh vs logout:
   - Simultaneous refresh and logout operations on the same session execute without deadlock.
3. Concurrent registration:
   - Simultaneous registration with identical email handles PostgreSQL unique constraint conflict
     cleanly, rolling back and raising EmailAlreadyExistsException without 500 crashes.
"""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import delete, select

from app.core.exceptions import AuthenticationFailedException, EmailAlreadyExistsException
from app.modules.audit.models import SecurityEvent
from app.modules.auth.models import RefreshToken, SessionStatus
from app.modules.auth.models import Session as UserSession
from app.modules.auth.service import (
    authenticate_user,
    register_user,
    revoke_session,
    rotate_refresh_token,
)
from app.modules.rbac.models import UserRole
from app.modules.users.models import User
from tests.conftest import TestSessionLocal


def _cleanup_test_user(user_id: uuid.UUID) -> None:
    """Scoped teardown: cleans up only records created by the specific test user."""
    with TestSessionLocal() as session:
        session.execute(delete(SecurityEvent).where(SecurityEvent.user_id == user_id))
        # Find session IDs for this user
        session_ids = (
            session.execute(select(UserSession.id).where(UserSession.user_id == user_id))
            .scalars()
            .all()
        )
        if session_ids:
            session.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(session_ids)))
            session.execute(delete(UserSession).where(UserSession.id.in_(session_ids)))
        session.execute(delete(UserRole).where(UserRole.user_id == user_id))
        session.execute(delete(User).where(User.id == user_id))
        session.commit()


def test_concurrent_refresh_token_rotation_reuse_detection():
    """Verify that concurrent rotation of the same refresh token prevents race conditions and deadlocks.

    Exactly one thread must succeed, and the concurrent competitor must be blocked by
    PostgreSQL FOR UPDATE row locks, observe the consumed token upon unblocking,
    and trigger reuse detection.
    """
    email = f"concurrency_rot_{uuid.uuid4().hex[:10]}@unitecare-test.org"
    password = "SecurePassword123!"

    with TestSessionLocal() as setup_db:
        user = register_user(setup_db, email=email, password=password)
        _, session, _, raw_refresh = authenticate_user(
            setup_db,
            email=email,
            password=password,
            ip_address="127.0.0.1",
            user_agent="ConcurrencyClient/1.0",
        )
        user_id = user.id
        session_id = session.id

    barrier = threading.Barrier(2)
    results = []

    def _worker(thread_idx: int):
        with TestSessionLocal() as db:
            barrier.wait()  # Synchronize both threads to start simultaneously
            try:
                _new_at, new_rt, _exp = rotate_refresh_token(
                    db=db,
                    raw_token=raw_refresh,
                    ip_address="127.0.0.1",
                    user_agent=f"Worker/{thread_idx}",
                )
                results.append(("SUCCESS", thread_idx, new_rt))
            except AuthenticationFailedException as exc:
                results.append(("REUSE_DETECTED", thread_idx, str(exc)))
            except Exception as exc:  # noqa: BLE001
                results.append(("ERROR", thread_idx, type(exc).__name__, str(exc)))

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(_worker, i) for i in range(2)]
            for f in futures:
                f.result(timeout=10)

        # Assertions: exactly one success, exactly one reuse detection, no errors/deadlocks
        statuses = [r[0] for r in results]
        assert "SUCCESS" in statuses, f"Expected one successful rotation, got: {results}"
        assert "REUSE_DETECTED" in statuses, f"Expected one reuse detection, got: {results}"
        assert len(statuses) == 2

        # Verify database state
        with TestSessionLocal() as verify_db:
            sess = verify_db.get(UserSession, session_id)
            assert sess is not None
            # Because reuse detection occurred on the session family, the session must be revoked
            assert sess.status == SessionStatus.REVOKED
    finally:
        _cleanup_test_user(user_id)


def test_concurrent_refresh_and_logout_no_deadlock():
    """Verify concurrent refresh and logout on the same session execute without PostgreSQL deadlock."""
    email = f"concurrency_logout_{uuid.uuid4().hex[:10]}@unitecare-test.org"
    password = "SecurePassword123!"

    with TestSessionLocal() as setup_db:
        user = register_user(setup_db, email=email, password=password)
        _, session, _, raw_refresh = authenticate_user(
            setup_db,
            email=email,
            password=password,
            ip_address="127.0.0.1",
            user_agent="ConcurrencyClient/1.0",
        )
        user_id = user.id
        session_id = session.id

    barrier = threading.Barrier(2)
    results = []

    def _refresh_worker():
        with TestSessionLocal() as db:
            barrier.wait()
            try:
                rotate_refresh_token(
                    db=db,
                    raw_token=raw_refresh,
                    ip_address="127.0.0.1",
                    user_agent="Worker/Refresh",
                )
                results.append(("REFRESH_SUCCESS", None))
            except AuthenticationFailedException as exc:
                results.append(("REFRESH_REJECTED", str(exc)))
            except Exception as exc:  # noqa: BLE001
                results.append(("REFRESH_ERROR", type(exc).__name__))

    def _logout_worker():
        with TestSessionLocal() as db:
            barrier.wait()
            try:
                revoke_session(db=db, session_id=session_id, user_id=user_id)
                results.append(("LOGOUT_SUCCESS", None))
            except Exception as exc:  # noqa: BLE001
                results.append(("LOGOUT_ERROR", type(exc).__name__))

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(_refresh_worker)
            f2 = executor.submit(_logout_worker)
            f1.result(timeout=10)
            f2.result(timeout=10)

        # Neither worker should fail with a deadlock (DBAPIError / DeadlockDetected)
        error_types = [r[0] for r in results if "ERROR" in r[0]]
        assert not error_types, f"Deadlock or unhandled error occurred: {results}"

        # Session must ultimately be REVOKED
        with TestSessionLocal() as verify_db:
            sess = verify_db.get(UserSession, session_id)
            assert sess is not None
            assert sess.status == SessionStatus.REVOKED
    finally:
        _cleanup_test_user(user_id)


def test_concurrent_registration_unique_constraint():
    """Verify concurrent registration with identical email cleanly handles PostgreSQL conflict."""
    email = f"concurrency_reg_{uuid.uuid4().hex[:10]}@unitecare-test.org"
    password = "SecurePassword123!"

    barrier = threading.Barrier(2)
    results = []
    created_user_id = None

    def _reg_worker(thread_idx: int):
        with TestSessionLocal() as db:
            barrier.wait()
            try:
                user = register_user(db=db, email=email, password=password)
                results.append(("CREATED", thread_idx, user.id))
            except EmailAlreadyExistsException:
                results.append(("CONFLICT_HANDLED", thread_idx, None))
            except Exception as exc:  # noqa: BLE001
                results.append(("ERROR", thread_idx, type(exc).__name__))

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(_reg_worker, i) for i in range(2)]
            for f in futures:
                f.result(timeout=10)

        statuses = [r[0] for r in results]
        assert "CREATED" in statuses, f"Expected one registration to succeed: {results}"
        assert "CONFLICT_HANDLED" in statuses, (
            f"Expected second registration to raise conflict: {results}"
        )
        assert len(statuses) == 2

        for r in results:
            if r[0] == "CREATED":
                created_user_id = r[2]
    finally:
        if created_user_id:
            _cleanup_test_user(created_user_id)
