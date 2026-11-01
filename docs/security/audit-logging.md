# Security Event Audit Logging Specification

## 1. Overview and Invariants

UniteCare provides an append-only security audit log in the `security_events` table to support non-repudiation, intrusion analysis, and compliance auditing.

### Invariants:
* **Append-Only**: No updates or deletes are permitted on `security_events`.
* **Zero Credential Leakage**: Passwords, hashes, raw tokens, cookies, or signing keys are strictly forbidden. The service employs recursive automated redaction to replace any sensitive keys or patterns with `[REDACTED]`.
* **Controlled Vocabulary**: Event types are constrained by the `SecurityEventType` enumeration.
* **Transactional Atomicity**: Audit event logging is committed in the exact same database transaction as the business state transition (registration, token rotation, password change), preventing desynchronization.

---

## 2. Recursive Redaction Engine

The audit logging subsystem (`app.modules.audit.service`) sanitizes all event metadata prior to persistence:
1. **Sensitive Key Redaction**: Any dictionary key matching sensitive substrings (`password`, `token`, `secret`, `jwt`, `key`, `auth`, `cookie`, `credential`, `bearer`, `private`, `database_url`) immediately redacts its associated value to `[REDACTED]`, regardless of whether the value is a primitive, list, or nested object.
2. **Deep Recursive Traversal**: Nested dictionaries, lists, sets, and tuples are traversed recursively.
3. **Pattern-Based String Redaction**:
   - Authorization headers (`Bearer <token>`) and compact JWT strings (`eyJ...`) within lists or non-sensitive dictionary values are automatically redacted.
   - Cookie key-value assignments containing sensitive tokens (`refresh_token=...`, `session=...`, `jwt=...`) are automatically redacted.

---

## 3. Supported Event Types

| Event Type | Trigger Description |
|---|---|
| `ACCOUNT_REGISTERED` | New user registered with local credentials |
| `LOGIN_SUCCESS` | Successful authentication; session and tokens issued |
| `LOGIN_FAILED` | Failed login attempt (invalid credentials, suspended account, unknown user) |
| `SESSION_CREATED` | New device session established |
| `SESSION_REVOKED` | Session terminated via logout, logout-all, or password reset |
| `SESSION_EXPIRED` | Session reached natural expiration |
| `REFRESH_TOKEN_ROTATED` | Refresh token successfully rotated |
| `REFRESH_TOKEN_REUSE_DETECTED` | Critical security alert: replay of consumed refresh token detected |
| `PASSWORD_CHANGED` | User changed password; active sessions terminated |
| `ACCOUNT_SUSPENDED` | Administrative suspension applied |
| `ACCOUNT_DISABLED` | Administrative deactivation applied |
| `ACCOUNT_REACTIVATED` | Account restored to active status |
| `ROLE_ASSIGNED` | Administrative assignment of a role to a user |
| `ROLE_REMOVED` | Removal of an assigned role from a user |

---

## 4. Schema Structure

* `id`: UUID Primary Key
* `user_id`: UUID FK `users.id` (ON DELETE SET NULL)
* `session_id`: UUID FK `sessions.id` (ON DELETE SET NULL)
* `event_type`: `VARCHAR(64)`
* `ip_address`: PostgreSQL `INET` (validated with standard Python `ipaddress`)
* `user_agent`: `TEXT`
* `metadata`: `JSONB` (default `{}`)
* `created_at`: `TIMESTAMPTZ` (default `now()`)

Index: `ix_security_events_user_id_created_at_desc` on `(user_id, created_at DESC)`.

