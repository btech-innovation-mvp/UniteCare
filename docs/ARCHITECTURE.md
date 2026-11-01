# UniteCare Architecture Specification

## 1. Architectural Philosophy: Modular Monolith

UniteCare adopts a **Modular Monolith** pattern for the centralized backend. This design provides:
- High developer velocity and simplified deployment without premature microservices complexity.
- Strict logical boundaries between internal modules (`auth`, `users`, `rbac`, `organizations`, `audit`).
- Transactional integrity guarantees provided natively by PostgreSQL across domain boundaries.
- Clean migration paths should specific submodules require independent scaling in future phases.

```
+-----------------------------------------------------------------------------------+
|                                  Client Layers                                    |
|                                                                                   |
|    +------------------------------------+   +--------------------------------+    |
|    | Admin Web Application (Next.js 15) |   | Mobile Application (Expo / RN) |    |
|    +------------------------------------+   +--------------------------------+    |
+-----------------------------------------------------------------------------------+
                                         |  HTTPS / REST
                                         v
+-----------------------------------------------------------------------------------+
|                             FastAPI Central Gateway                               |
|                                                                                   |
|          +-------------------+     +-------------------+                          |
|          | Security Headers  |     |   CORS Middleware |                          |
|          +-------------------+     +-------------------+                          |
|                                                                                   |
|                               API Router (/api/v1)                                |
+-----------------------------------------------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         v                               v                               v
+------------------+           +-------------------+           +-------------------+
|   auth module    |           |   users module    |           |    rbac module    |
| - Password hash  |           | - Account profile |           | - Roles & Perms   |
| - JWT & Sessions |           | - Status checks   |           | - Unified RBAC    |
| - Token rotation |           | - Verification    |           | - Guard deps      |
+------------------+           +-------------------+           +-------------------+
         |                               |                               |
         +-------------------------------+-------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                                                               |
         v                                                               v
+-----------------------+                                     +---------------------+
| organizations module  |                                     |    audit module     |
| - NGOs                |                                     | - Immutable logs    |
| - Memberships         |                                     | - Sanitized details |
| - Org-scoped RBAC     |                                     | - Event recorder    |
+-----------------------+                                     +---------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        Data Access Layer (SQLAlchemy 2.0)                         |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             PostgreSQL 16 Database                                |
+-----------------------------------------------------------------------------------+
```

---

## 2. Module Boundaries

1. **`app.core`**:
   - Application configuration (`config.py`) via Pydantic Settings.
   - Cryptographic primitives (`security.py`): Argon2id/bcrypt password hashing, JWT encoding/decoding, token hash generation.
   - Centralized domain exceptions and handlers.
2. **`app.db`**:
   - SQLAlchemy Declarative Base with common timestamps (`created_at`, `updated_at`).
   - Engine and sessionmaker lifecycle (`session.py`) yielding scoped sessions per request.
3. **`app.modules.auth`**:
   - Authentication services, session creation, refresh token rotation, token family tracking, and reuse detection.
4. **`app.modules.users`**:
   - User account models, profile endpoints, account status validation.
5. **`app.modules.rbac`**:
   - Unified Role-Based Access Control. Role and Permission entity definitions.
   - Dependency guards (`require_permission`, `require_role`).
6. **`app.modules.organizations`**:
   - NGO entities and NGO memberships (`ngo_memberships`).
   - Organization-scoped permission checks (`require_ngo_admin`).
7. **`app.modules.audit`**:
   - Immutable audit logging. Sanitized JSONB data capture (never logging passwords or tokens).

---

## 3. Data Protection and Network Boundary

- **Backend Authority**: Clients cannot escalate privileges, set roles, or bypass status checks.
- **Strict CORS**: Whitelisted origins only (`NEXT_PUBLIC_API_URL`, local web/mobile development origins).
- **Environment Isolation**: Database credentials, encryption keys, and tokens are read strictly from environment variables.
