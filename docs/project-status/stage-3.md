# Stage 3 Status Report — Identity, Authentication, and RBAC

## 1. Stage Summary
Stage 3F of the UniteCare project implements the centralized Identity, Authentication, Persistent Session Management, Refresh-Token Rotation with Reuse Detection, and Permission-Based RBAC architecture.

All features strictly adhere to scope boundaries: zero future domain logic (NGO workflows, volunteer/donor management, AI, drones) was introduced. Zero fake users or mock records exist in the database.

---

## 2. Completed Capabilities

1. **User Identity Model**: `users` table with UUID primary key, `AccountStatus` lifecycle states, and functional unique index `LOWER(email)`.
2. **Local Authentication**: `auth_identities` table supporting bcrypt-hashed local credentials with strict UTF-8 72-byte limit validation.
3. **Short-Lived JWT Access Tokens**: 15-minute expiration carrying minimal claims (`sub`, `sid`, `jti`, `iat`, `exp`). Zero sensitive or stale role claims.
4. **Persistent Sessions**: `sessions` table capturing client device context, IP address (PostgreSQL `INET`), user agent, and activity timestamps.
5. **Atomic Refresh Token Rotation**: Row-level `SELECT ... FOR UPDATE` locking preventing race conditions during concurrent refresh requests.
6. **Refresh Token Family Reuse Detection**: Immediate invalidation of all tokens sharing a `family_id` and revocation of the parent session upon detection of token replay.
7. **Session Revocation**: Single session logout and multi-device `logout-all` invalidating all session context and refresh chains.
8. **Permission-Based RBAC**: Relational role-permission architecture resolving granular permissions dynamically. Baseline system configuration role `public_user` holds zero directory permissions under least privilege. Standard permissions (`users:read`, `users:manage`, `ngos:read`, `ngos:manage`) are granted only through explicitly assigned roles.
9. **Append-Only Security Audit Logging**: `security_events` table capturing all authentication and lifecycle events with automatic recursive redaction of sensitive credentials, Bearer headers, and embedded tokens.
10. **Automated Testing & Concurrency Suite**: Comprehensive tests covering database constraints, migrations, registration, login, token pipeline, refresh rotation, reuse detection, logout, password changes, RBAC, recursive audit redaction, and multi-threaded PostgreSQL concurrency.
11. **Isolated Test Harness**: Dedicated test database (`unitecare_test_db`) with exact allowlist pre-run validation refusing to run against any other database, and transactional savepoint isolation eliminating destructive global table deletions.
12. **Hierarchical Concurrency Locking**: Parent `UserSession` locked before child `RefreshToken`, preventing AB-BA PostgreSQL deadlocks.
13. **Account Enumeration Prevention**: Uniform 401 response (`"Invalid email or password."`) across invalid credentials, non-existent users, suspended accounts, and disabled accounts.
14. **Process-Local Rate Limiting**: Sliding-window rate limiting (10 attempts/min for login, 5 attempts/min for registration) protecting authentication endpoints against brute force attacks. Explicitly documented as process-local in Stage 3.


---

## 3. Infrastructure & Isolation Verification
* **PostgreSQL Service**: Running on host port **5433** (`unitecare_postgres`).
* **Test Database**: Dedicated `unitecare_test_db` created and migrated with revision `d73f7565f105`.
* **Neighbor Database**: The existing `transit-db` container on host port **5432** was completely untouched and remains healthy.
* **Database State**: Zero fake users or mock profiles exist in development (`unitecare_db` users=0, security_events=0, user_roles=0). Zero test mutations leak into development.

