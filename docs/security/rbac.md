# Role-Based Access Control (RBAC) Specification

## 1. Permission-Oriented Authorization

UniteCare enforces **Permission-Based RBAC**, strictly separating permissions (actions that can be performed) from roles (groupings of permissions assigned to users).

### Conceptual Chain
```
USER ──(user_roles)──> ROLE ──(role_permissions)──> PERMISSION
```

### Architectural Rules
* **No Hardcoded Role Checks**: Application endpoints never check `if user.role == "admin"` or `if "ngo_manager" in user.roles`.
* **Explicit Permission Verification**: Endpoints enforce granular capabilities using FastAPI dependencies:
  ```python
  @router.get("/protected", dependencies=[Depends(require_permission("users:manage"))])
  def protected_endpoint(): ...
  ```
* **Extensibility**: Future domain roles (e.g. `ngo_manager`, `volunteer_coordinator`, `impact_auditor`) can be introduced by creating a role and mapping permissions without modifying API endpoint logic.

---

## 2. Implemented Schema

1. `roles`:
   - `id`: UUID Primary Key
   - `name`: `VARCHAR(64)` UNIQUE (e.g. `public_user`)
   - `description`: `TEXT`
   - `created_at`: `TIMESTAMPTZ`
2. `permissions`:
   - `id`: UUID Primary Key
   - `name`: `VARCHAR(64)` UNIQUE (e.g. `users:read`, `users:manage`)
   - `description`: `TEXT`
   - `created_at`: `TIMESTAMPTZ`
3. `user_roles`:
   - `user_id`: UUID FK `users.id` (ON DELETE CASCADE)
   - `role_id`: UUID FK `roles.id` (ON DELETE CASCADE)
   - `assigned_at`: `TIMESTAMPTZ`
   - `assigned_by`: UUID FK `users.id` (ON DELETE SET NULL, nullable for system registration)
   - Primary Key: `(user_id, role_id)`
4. `role_permissions`:
   - `role_id`: UUID FK `roles.id` (ON DELETE CASCADE)
   - `permission_id`: UUID FK `permissions.id` (ON DELETE CASCADE)
   - Primary Key: `(role_id, permission_id)`

---

## 3. Baseline System Seeds (Configuration Records)

Per the genuine-data rule, no fake users are seeded. Only the required baseline configuration records are initialized:

* **Role**: `public_user` (assigned automatically to newly registered accounts). Holds zero directory-level permissions under the principle of least privilege.
* **Standard Permissions**:
  - `users:read`: Directory-level capability to read other user profiles and accounts (reserved for administrative or coordinator roles; viewing one's own account at `/api/v1/auth/me` requires only active authentication, not `users:read`).
  - `users:manage`: Administrative user management and role assignment.
  - `ngos:read`: Read registered NGO listings.
  - `ngos:manage`: Verify and manage NGO credentials.

