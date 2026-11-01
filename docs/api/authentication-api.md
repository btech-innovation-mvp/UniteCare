# Authentication API Specification

Base URL prefix: `/api/v1/auth`

All request and response bodies use JSON (`application/json`).
All protected endpoints require the HTTP header:
`Authorization: Bearer <access_token>`

---

## 1. Register User Account
`POST /api/v1/auth/register`

Creates a new user, hashes the password with direct bcrypt, establishes a local auth identity, and assigns the default `public_user` role.

### Request Body
```json
{
  "email": "user@example.org",
  "password": "SecurePassword123!"
}
```

### Constraints:
* `email`: Valid email syntax, automatically normalized to lower case.
* `password`: Minimum 8 characters, maximum 72 UTF-8 bytes.

### Response `201 Created`
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.org",
  "account_status": "ACTIVE",
  "created_at": "2026-09-30T15:00:00Z",
  "updated_at": "2026-09-30T15:00:00Z"
}
```

### Error Codes
* `409 Conflict`: Email already exists (handled cleanly even under concurrent registration conflicts).
* `422 Unprocessable Content`: Validation failure (short password, >72 bytes, malformed email).
* `429 Too Many Requests`: Registration rate limit exceeded (maximum 5 attempts/minute per IP, returns `Retry-After` header).

---

## 2. Authenticate User (Login)
`POST /api/v1/auth/login`

Validates credentials, creates a persistent session, generates a high-entropy refresh token, and issues a short-lived access JWT.
Protected by process-local sliding-window rate limiting (maximum 10 attempts/minute per IP; process-local, not distributed across multi-worker clusters).

### Request Body
```json
{
  "email": "user@example.org",
  "password": "SecurePassword123!"
}
```

### Response `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
  "token_type": "bearer",
  "expires_in": 900,
  "refresh_token": "nK82hG...48_bytes_entropy_token"
}
```

### Error Codes
* `401 Unauthorized`: Generic `"Invalid email or password."` returned identically across invalid credentials, unknown emails, suspended accounts, and disabled accounts to prevent account enumeration.
* `429 Too Many Requests`: Login rate limit exceeded (maximum 10 attempts/minute per IP, returns `Retry-After` header).


---

## 3. Refresh Access Token
`POST /api/v1/auth/refresh`

Rotates an opaque refresh token with atomic concurrency locking (`SELECT ... FOR UPDATE`) and family reuse detection.
Enforces hierarchical locking (`UserSession` -> `RefreshToken`) to eliminate PostgreSQL deadlocks.

### Request Body
```json
{
  "refresh_token": "nK82hG...48_bytes_entropy_token"
}
```

### Response `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
  "token_type": "bearer",
  "expires_in": 900,
  "refresh_token": "next_rotated_opaque_token"
}
```

### Error Codes
* `401 Unauthorized`: Token invalid, expired, revoked, or reuse detected (which terminates the session).

---

## 4. Logout (Current Session)
`POST /api/v1/auth/logout`
**Protected** (Bearer token required)

Revokes the current device session and all associated refresh tokens using hierarchical locking.

### Response `204 No Content`

---

## 5. Logout All (Global Session Revocation)
`POST /api/v1/auth/logout-all`
**Protected** (Bearer token required)

Terminates all active sessions and refresh chains across all client devices for the authenticated user.

### Response `204 No Content`

---

## 6. Change Password
`POST /api/v1/auth/change-password`
**Protected** (Bearer token required)

Verifies the current password, updates the bcrypt hash, and invalidates all existing sessions in an atomic database transaction.

### Request Body
```json
{
  "current_password": "SecurePassword123!",
  "new_password": "NewStrongPassword456!"
}
```

### Response `200 OK`
```json
{
  "message": "Password changed successfully. All previous sessions have been revoked."
}
```

---

## 7. Get Current User Profile
`GET /api/v1/auth/me`
**Protected** (Bearer token required)

Returns the safe identity details of the authenticated actor.

### Response `200 OK`
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.org",
  "account_status": "ACTIVE",
  "created_at": "2026-09-30T15:00:00Z",
  "updated_at": "2026-09-30T15:00:00Z"
}
```

---

## 8. Get Effective Permissions
`GET /api/v1/auth/permissions`
**Protected** (Bearer token required)

Returns the resolved set of distinct system permissions granted to the authenticated user via their assigned roles.
Newly registered `public_user` accounts start with empty permissions (`[]`) under least privilege.

### Response `200 OK` (Default Public User)
```json
{
  "permissions": []
}
```

### Response `200 OK` (User With Assigned Roles)
```json
{
  "permissions": [
    "ngos:read",
    "users:read"
  ]
}
```


