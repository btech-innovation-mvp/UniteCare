# ADR-004: Refresh-Token Rotation and Family Reuse Detection

## Status
Accepted

## Context
Stateless JWT access tokens present a revocation challenge: once issued, they cannot be invalidated without distributed blocklists. Conversely, long-lived refresh tokens present a major theft risk if exposed on client devices.

## Decision
1. Access tokens are short-lived (15 minutes).
2. Refresh tokens are opaque, cryptographically random strings (48 bytes entropy).
3. The database stores ONLY the SHA-256 hash of refresh tokens.
4. Refresh tokens are grouped into families (`family_id`).
5. Rotation is atomic, utilizing row-level `SELECT ... FOR UPDATE` database locking.
6. Replay of an already-used or revoked refresh token triggers immediate **Reuse Detection**: revoking the entire token family and associated session.

## Consequences
### Positive:
* Token theft is detected automatically upon subsequent legitimate or illegitimate rotation attempts.
* Zero plaintext tokens are stored in the database.
* Concurrency race conditions between simultaneous refresh requests are prevented via row-level locks.

### Trade-offs:
* Refresh requests require a PostgreSQL database write and row-level lock. Redis may be introduced in future phases for high-throughput scaling.
