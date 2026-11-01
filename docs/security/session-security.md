# Session Security Specification

## 1. Persistent Sessions Architecture

A `Session` record in UniteCare represents a single authenticated client device context (e.g., Desktop Web, Mobile App, Tablet).

### Schema (`sessions`)
* `id`: UUID (Primary Key, matches `sid` claim in JWT access token)
* `user_id`: UUID (Foreign Key `users.id` with `ON DELETE CASCADE`)
* `status`: `SessionStatus` (`ACTIVE`, `REVOKED`, `EXPIRED`)
* `ip_address`: PostgreSQL `INET` (nullable)
* `user_agent`: `TEXT` (nullable)
* `last_seen_at`: `TIMESTAMPTZ` (updated on client activity)
* `expires_at`: `TIMESTAMPTZ` (default: 30 days)
* `created_at`: `TIMESTAMPTZ`

Index: `ix_sessions_user_id_status` on `(user_id, status)` for fast lifecycle queries.

---

## 2. Server-Side Session Enforcement and Activity Tracking

Unlike stateless JWT architectures where tokens remain valid until expiration regardless of administrative revocation, UniteCare validates the session on **every protected request**:

```python
session = db.get(UserSession, session_id)
if session is None or session.status != SessionStatus.ACTIVE or session.expires_at < now:
    if session and session.expires_at < now and session.status == SessionStatus.ACTIVE:
        session.status = SessionStatus.EXPIRED
        db.commit()
    raise AuthenticationFailedException("Session has been revoked or expired.")
```

* **Persisted Expiration**: When an active session passes its expiration window, its database status is persisted as `SessionStatus.EXPIRED`.
* **Throttled Activity Tracking (`last_seen_at`)**: To prevent database write amplification on high-frequency read requests, `session.last_seen_at` updates are throttled to a minimum interval of 60 seconds and flushed within the request's database transaction without out-of-band commits.

---

## 3. Hierarchical Concurrency Lock Ordering

To prevent PostgreSQL concurrency deadlocks between concurrent refresh token rotations and session revocations (logout), all mutating operations enforce strict hierarchical lock acquisition:
1. **Parent First**: `UserSession` row is locked first (`SELECT ... WHERE id = :session_id FOR UPDATE`).
2. **Child Second**: `RefreshToken` row is locked second (`SELECT ... WHERE id = :token_id FOR UPDATE`).

Because all competing workers follow the exact same acquisition hierarchy, AB-BA deadlock cycles are impossible.

---

## 4. Revocation Lifecycles

1. **Explicit Logout (`POST /api/v1/auth/logout`)**:
   - Acquires `UserSession` lock, then invalidates active refresh tokens.
   - Sets session status to `REVOKED`.
   - Records `SESSION_REVOKED` in audit logs.
2. **Global Logout (`POST /api/v1/auth/logout-all`)**:
   - Queries all active sessions for `user_id`.
   - Sets `status = REVOKED` across all of them.
   - Revokes all associated refresh token chains.
3. **Password Change Revocation (`POST /api/v1/auth/change-password`)**:
   - Upon successful verification and password update, all active sessions and refresh chains are revoked atomically within the same transaction.
   - Enforces re-authentication across all user devices.
4. **Token Reuse Revocation**:
   - Detected replay of a used refresh token immediately revokes the entire token family and the associated session.

