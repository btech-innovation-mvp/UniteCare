# ADR-006: Hierarchical Concurrency Locking and Fail-Closed Test Isolation

## Status
Accepted

## Context
During Stage 3F concurrency and audit evaluations, two critical reliability concerns were identified:
1. **Concurrency Deadlocks**: Independent refresh token rotation and logout operations locked database rows in conflicting orders (`RefreshToken` first vs. `UserSession` first), creating potential AB-BA deadlocks in PostgreSQL under high concurrency.
2. **Test Environment Hazards & Global Deletions**: Running destructive test teardowns (`DELETE FROM users; DELETE FROM security_events;`) against shared database environments risks corrupting development or staging state if misconfigured.

## Decision
1. **Hierarchical Lock Ordering**:
   All session-mutating operations enforce strict hierarchical row-locking order:
   - Acquire lock on parent `UserSession` row first (`SELECT ... WHERE id = :session_id FOR UPDATE`).
   - Acquire lock on child `RefreshToken` row second (`SELECT ... WHERE id = :token_id FOR UPDATE`).
   This eliminates lock cycles across all concurrent operations (refresh, logout, reuse detection).
2. **Dedicated Test Database & Exact Allowlist Safeguard**:
   - Tests execute strictly and exclusively against the isolated test database (`unitecare_test_db`).
   - A fail-closed safeguard in `conftest.py` inspects the active database URL before test collection; automated tests refuse to run unless the configured database name is exactly `unitecare_test_db`. Development (`unitecare_db`), production, neighbor (`transit-db`), and other databases are rejected immediately without establishing a connection.
3. **Savepoint Transaction Isolation**:
   - Pytest fixtures use SQLAlchemy 2.0 transactional savepoints (`join_transaction_mode="create_savepoint"`).
   - All mutations within tests are rolled back at fixture teardown without executing destructive global `DELETE` statements.
4. **Authentication Rate Limiting Boundary**:
   - Authentication endpoints enforce sliding-window rate limiting (10 attempts/min for login, 5 attempts/min for registration).
   - In Stage 3, this rate limiter is implemented in process memory (`InMemoryRateLimiter`). It is process-local and explicitly documented as insufficient for multi-worker or multi-replica production environments without a distributed cache (Redis) or reverse proxy / API Gateway.

## Consequences
### Positive:
* Complete elimination of PostgreSQL deadlocks under concurrent authentication requests.
* Development and production databases are physically protected from test suite execution by an exact allowlist.
* 100% test isolation with zero residual test data or global table locks.

### Trade-offs:
* Multi-threaded concurrency tests require dedicated independent connections and explicit scoped entity cleanup rather than relying solely on savepoints.
* Production deployments utilizing multiple Uvicorn workers or container replicas must adopt Redis or API Gateway rate limiting for global enforcement.

