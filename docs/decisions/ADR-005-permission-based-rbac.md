# ADR-005: Permission-Based Role-Based Access Control (RBAC)

## Status
Accepted

## Context
Traditional role-checking systems scatter string comparisons throughout endpoint code (e.g. `if user.role == 'admin':`). This tightly couples API routes to specific administrative roles, making the introduction of nuanced domain roles (e.g., NGO managers, regional coordinators, auditors) brittle and requiring extensive code refactoring.

## Decision
1. Separate Users, Roles, and Permissions into a 5-table relational structure:
   `users` ── `user_roles` ── `roles` ── `role_permissions` ── `permissions`.
2. Endpoint dependencies check granular permissions (e.g., `require_permission("users:manage")`), never role names.
3. Access tokens carry zero role or permission claims; permissions are resolved dynamically from the database per request.
4. Newly registered users are assigned the baseline `public_user` role under the principle of least privilege (zero administrative or user-directory permissions). Self-profile inspection (`/api/v1/auth/me`) requires only valid session authentication, while directory permissions (`users:read`, `users:manage`) are reserved for explicitly assigned administrative or coordinator roles.


## Consequences
### Positive:
* Endpoints remain decoupled from role taxonomy.
* Introducing new roles or reconfiguring permission sets is purely a database configuration change requiring zero API code alterations.
* Revoking a role immediately takes effect on the user's next request without token invalidation latency.

### Trade-offs:
* Requires a fast index join query per protected request, which will benefit from Redis caching in future scale phases.
