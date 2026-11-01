# UniteCare Authentication, Authorization, and Role Architecture

## 1. Authentication Lifecycle

### Initial Prototype Scope
The initial version implements **Email + Password** authentication exclusively. Integrations for **Phone OTP** and **Google Sign-In** are deferred to **Stage 7** to eliminate premature external dependencies while preserving the schema foundation.

### Token Strategy
UniteCare employs a dual-token architecture:

| Token Type | Medium | Expiry | Storage | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Access Token** | JWT | 15 Minutes | In-Memory (Web) / Encrypted (Mobile) | Stateless authorization against protected endpoints. |
| **Refresh Token** | Cryptographic String | 7 Days (Web) / 30 Days (Mobile) | Database (Hashed SHA-256) | Long-lived session renewal with rotation. |

### Transactional Refresh Token Rotation & Family Reuse Detection
To prevent refresh token hijacking:
1. Every session is tagged with a unique `family_id: UUID`.
2. When `/api/v1/auth/refresh` is invoked:
   - The current refresh token is marked as consumed (`revoked_at = now()`).
   - A new refresh token is issued and assigned to the same `family_id`.
   - A new access token is returned.
3. **Reuse Detection**: If an incoming request presents an already-consumed or revoked refresh token, the backend detects token replay/theft. It immediately **revokes the entire family** (`UPDATE user_sessions SET revoked_at = now() WHERE family_id = :family_id`), terminates all associated sessions, and emits a critical security audit event.

---

## 2. Registration Rules & Account Status

### Default Role Assignment: `public_user`
- Registration alone does **not** make an applicant a volunteer or donor.
- Public self-registration automatically assigns exclusively the base role: **`public_user`**.
- Any role field submitted in a client registration request is strictly ignored.

### Role Transition Workflow
- **Volunteers**: A user holding `public_user` status must apply for an approved NGO affiliation. Only upon approval by an NGO administrator does the user gain field volunteer permissions within that NGO.
- **Donors**: Donor onboarding and verification will be handled in a dedicated future stage.
- **System Administrators**: Administrative roles (`system_admin`, `community_admin`) are granted exclusively via authorized backend admin workflows or the secure initial bootstrap CLI.

### Account Status Lifecycle
- `ACTIVE`: Normal operational state. Default state upon registration.
- `SUSPENDED`: Temporarily blocked by an administrator due to security or compliance review.
- `DISABLED`: Permanently deactivated by administrative action or account closure.

> **Status Enforcement**: Every token verification query evaluates `users.account_status`. Requests from `SUSPENDED` or `DISABLED` accounts are rejected immediately with `401 Unauthorized` and cannot obtain new tokens or access protected endpoints. For complete details, see [Identity & Auth Architecture](architecture/identity-auth-architecture.md) and [Security Model](security/security-model.md).

---

## 3. Unified Role-Based Access Control (RBAC)

UniteCare rejects boolean superuser flags (such as `is_superuser`) in favor of a clean, unified RBAC architecture:

```
[User Account]
      |
      +---> user_roles (System Scope)
      |          |
      |          +---> 'system_admin'     --> System-wide management permissions
      |          +---> 'community_admin'  --> Regional coordination permissions
      |          +---> 'public_user'      --> Baseline public access
      |
      +---> ngo_memberships (Organization Scope)
                 |
                 +---> NGO 'Hope Foundation'
                 |          Role: 'admin'     --> Administer Hope Foundation only
                 |
                 +---> NGO 'Community Health'
                            Role: 'volunteer' --> Field access in Community Health only
```

- **System Roles**: Governed by `roles`, `permissions`, `role_permissions`, and `user_roles`.
- **Organization Roles**: Governed by `ngo_memberships` with scoped roles (`admin`, `staff`, `volunteer`, `member`).
- **Authorization Guard**: An NGO administrator in NGO-A has zero administrative authority in NGO-B or across the global platform.
