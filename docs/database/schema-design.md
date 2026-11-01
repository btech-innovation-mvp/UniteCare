# Database Schema Design — Stage 3

## 1. Overview & Connection Architecture

The UniteCare relational schema is deployed on PostgreSQL 16. In accordance with platform isolation policies, the UniteCare database container runs on host port **5433** (container port 5432), completely isolating it from the host's existing `transit-db` container running on port 5432.

---

## 2. Table Specifications

### Identity & Authentication Tables

```
                    ┌─────────────────────────┐
                    │          users          │
                    ├─────────────────────────┤
                    │ id (UUID, PK)           │
                    │ email (VARCHAR(255))    │◄─── UNIQUE(LOWER(email))
                    │ account_status (ENUM)   │
                    │ created_at (TIMESTAMPTZ)│
                    │ updated_at (TIMESTAMPTZ)│
                    └───────────┬─────────────┘
                                │ 1:N (CASCADE)
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ auth_identities  │  │     sessions     │  │   security_events    │
├──────────────────┤  ├──────────────────┤  ├──────────────────────┤
│ id (PK)          │  │ id (PK, JWT sid) │  │ id (PK)              │
│ user_id (FK)     │  │ user_id (FK)     │  │ user_id (FK NULL)    │
│ provider (local) │  │ status (ACTIVE..)│  │ session_id (FK NULL) │
│ password_hash    │  │ ip_address (INET)│  │ event_type (VARCHAR) │
│ created_at / up..│  │ user_agent (TEXT)│  │ ip_address (INET)    │
└──────────────────┘  │ last_seen_at     │  │ user_agent (TEXT)    │
                      │ expires_at       │  │ metadata (JSONB)     │
                      │ created_at       │  │ created_at (DESC idx)│
                      └─────────┬────────┘  └──────────────────────┘
                                │ 1:N (CASCADE)
                                ▼
                      ┌──────────────────┐
                      │  refresh_tokens  │
                      ├──────────────────┤
                      │ id (PK)          │
                      │ session_id (FK)  │
                      │ token_hash (SHA) │◄─── UNIQUE
                      │ family_id (UUID) │
                      │ issued_at        │
                      │ expires_at       │
                      │ used_at          │
                      │ revoked_at       │
                      └──────────────────┘
```

### Authorization (RBAC) Tables

```
┌──────────────┐          ┌──────────────┐          ┌─────────────────┐
│    users     │          │  user_roles  │          │      roles      │
├──────────────┤          ├──────────────┤          ├─────────────────┤
│ id (PK)      │◄─────────┤ user_id (FK) │   ┌─────►│ id (PK)         │
└──────────────┘          │ role_id (FK) ├───┘      │ name (VARCHAR)  │◄── UNIQUE
                          │ assigned_at  │          │ description     │
                          │ assigned_by  │          │ created_at      │
                          └──────────────┘          └────────┬────────┘
                                                             │
                                                             ▼
                                                    ┌─────────────────┐
                                                    │role_permissions │
                                                    ├─────────────────┤
                                                    │ role_id (FK)    │
                                                    │ permission_id(FK)
                                                    └────────┬────────┘
                                                             │
                                                             ▼
                                                    ┌─────────────────┐
                                                    │   permissions   │
                                                    ├─────────────────┤
                                                    │ id (PK)         │
                                                    │ name (VARCHAR)  │◄── UNIQUE
                                                    │ description     │
                                                    │ created_at      │
                                                    └─────────────────┘
```

---

## 3. Database Indexes

1. `users`:
   - `ix_users_lower_email`: Functional unique index on `LOWER(email)`
2. `sessions`:
   - `ix_sessions_user_id_status`: Compound index on `(user_id, status)`
3. `refresh_tokens`:
   - `ix_refresh_tokens_token_hash`: Unique index on `token_hash`
   - `ix_refresh_tokens_family_revoked`: Compound index on `(family_id, revoked_at)`
4. `security_events`:
   - `ix_security_events_user_id_created_at_desc`: Compound index on `(user_id, created_at DESC)`
5. `roles`:
   - `ix_roles_name`: Unique index on `name`
6. `permissions`:
   - `ix_permissions_name`: Unique index on `name`
