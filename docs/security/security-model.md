# UniteCare Security Model

## 1. Threat Model & Security Invariants

The UniteCare platform is designed to operate under hostile network environments, coordinating critical disaster relief and social impact initiatives. The security model addresses the following threat vectors:

1. **Credential Stuffing & Dictionary Attacks**: Mitigated by direct `bcrypt` hashing with 12 rounds and generic authentication failure responses that leak zero information about account existence.
2. **Session Hijacking & Token Theft**: Mitigated by short-lived JWT access tokens (15-minute default) paired with stateful PostgreSQL-backed sessions and refresh-token family reuse detection.
3. **Privilege Escalation**: Mitigated by permission-based RBAC resolved dynamically in the database; tokens carry zero permission or role claims, preventing stale claim exploitation.
4. **Data Tampering & Silent Truncation**: Explicit 72-byte UTF-8 password limits prevent the legacy bcrypt silent truncation vulnerability.
5. **Insider & Audit Tampering**: `security_events` table is append-only, capturing security-relevant lifecycle occurrences with automated redaction of sensitive credentials.

---

## 2. Authentication Request Pipeline

Every protected endpoint request follows an invariant 10-step pipeline:

```
[Request with Bearer Token]
          ↓
  1. Extract access token from HTTP Authorization header
          ↓
  2. Verify JWT signature against JWT_SECRET_KEY
          ↓
  3. Verify JWT expiration (exp) and issued-at (iat)
          ↓
  4. Identify User entity from sub claim
          ↓
  5. Check User account_status == AccountStatus.ACTIVE (reject 401 if SUSPENDED/DISABLED)
          ↓
  6. Identify Session entity from sid claim
          ↓
  7. Check Session status == SessionStatus.ACTIVE and expires_at > now()
          ↓
  8. Update Session last_seen_at = now()
          ↓
  9. Resolve required permission against user's assigned roles in PostgreSQL
          ↓
 10. Authorize (reject 403 if missing) and execute business logic
```

---

## 3. Error Handling and Disclosure Prevention

To prevent side-channel enumeration:
* **Registration**: 409 Conflict if email is already taken. 422 if input validation fails.
* **Authentication**: Returns `401 Unauthorized` with generic detail `"Invalid email or password."` regardless of whether the email was not found, the account was suspended, or the password was incorrect.
* **Database & Internal Errors**: Raw SQL errors, table names, connection strings, and stack traces are suppressed and logged internally, returning standard HTTP error payloads.

---

## 4. Rate Limiting, RBAC Least Privilege & Test Isolation Safeguards

### Process-Local Rate Limiting Boundaries
* **Endpoints**: Login (`RATE_LIMIT_LOGIN_PER_MINUTE=10`), Registration (`RATE_LIMIT_REGISTER_PER_MINUTE=5`).
* **Process-Local Scope**: The sliding-window rate limiter is implemented in process memory (`InMemoryRateLimiter`). It is process-local and does NOT share state across multiple Uvicorn worker processes or distributed container replicas.
* **Production Deployment Note**: Production environments with multiple worker processes or horizontal replicas require a distributed rate limiter (such as Redis token-bucket) or edge reverse-proxy enforcement (Cloudflare, NGINX, API Gateway).

### RBAC Least Privilege Baseline
* Newly registered accounts receive the `public_user` role, which holds **zero** directory-level permissions (`users:read` and `users:manage` are withheld).
* Reading self profile (`/api/v1/auth/me`) relies exclusively on active session authentication (`sub` claim matching the caller), preventing users from reading or managing other accounts.

### Test Database Exact Allowlist
* Automated tests enforce an exact allowlist: tests refuse to execute unless the configured test database name is exactly `unitecare_test_db`.
* Development (`unitecare_db`), production, and neighbor (`transit-db`) databases are rejected fail-closed before any database connection is opened.

