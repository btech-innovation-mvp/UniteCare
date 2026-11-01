# Token Security Specification

## 1. Access Token Design (JWT)

UniteCare implements short-lived JSON Web Tokens (JWT) signed via HMAC-SHA256 (`HS256`).

### Claims Invariant
Access tokens contain ONLY minimal cryptographic identity claims:

| Claim | Type | Description |
|---|---|---|
| `sub` | `str` (UUID) | User account identifier |
| `sid` | `str` (UUID) | Active Session identifier |
| `jti` | `str` (UUID) | Unique token instance identifier |
| `iat` | `int` (Unix seconds) | Token issuance timestamp |
| `exp` | `int` (Unix seconds) | Token expiration timestamp (default: 15 minutes) |

### Strict Exclusions
The following fields are strictly prohibited from appearing in JWT claims:
* **Passwords or hashes**
* **Refresh tokens**
* **Roles and permission lists** (authorizations are dynamic and resolved on every request to prevent stale privilege exploits)
* **Personally Identifiable Information (PII)**
* **Internal server or database credentials**

---

## 2. Refresh Token Design

Refresh tokens are opaque, high-entropy tokens allowing clients to obtain new access tokens without re-entering credentials.

### Cryptographic Invariants:
1. **High Entropy**: Generated via `secrets.token_urlsafe(48)` (384 bits of entropy).
2. **Zero Plaintext Persistence**: The raw refresh token is returned to the client once upon issuance and NEVER stored in the database.
3. **SHA-256 Hashing**: The database persists only the 64-character hexadecimal SHA-256 digest (`VARCHAR(64)` with a UNIQUE constraint).
4. **Token Family Grouping**: Every refresh token belongs to a `family_id` (UUID). When rotated legitimately, the successor token inherits the exact same `family_id`.

---

## 3. Refresh Token Rotation & Family Reuse Detection

To counter refresh token theft and replay attacks:
* When a valid refresh token is submitted to `/api/v1/auth/refresh`:
  1. The token is locked atomically via `SELECT ... FOR UPDATE`.
  2. If `used_at` or `revoked_at` is set, **Token Reuse is Detected**:
     - The entire token family (`family_id`) is revoked (`revoked_at = now()`).
     - The associated session is immediately marked `SessionStatus.REVOKED`.
     - An audit event `REFRESH_TOKEN_REUSE_DETECTED` is recorded.
     - The request is rejected with `401 Unauthorized`.
  3. If unconsumed, `used_at` is set to `now()`.
  4. A new refresh token is generated, hashed, and inserted with the same `family_id`.
  5. A new access token is issued to the client.
