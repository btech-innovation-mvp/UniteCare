# UniteCare

**UniteCare** is an AI-enabled social-impact coordination platform designed to connect NGOs, volunteers, social workers, donors, and administrators to coordinate community assistance.

> **Current Scope Notice (Prototype — Phase 0)**:
> Development is strictly scoped to the foundation: **Authentication, User Registration, Backend-Controlled Roles/RBAC, Secure Persistent Sessions, and Basic Web/Mobile Dashboards**.
> Advanced domain features (AI matching, drone/robotics dispatch, donation processing, impact reports, and complex NGO collaboration workflows) are deferred to later phases.

---

## 1. Non-Negotiable Data Policy

UniteCare enforces a strict **genuine-data policy**:

1. **No Mock Data**: No dummy users, fictional NGOs, fabricated volunteers, or dummy donors are ever seeded into the application database.
2. **No Fake Statistics**: Dashboards must never show fabricated counts, ratings, or activity indicators.
3. **Genuine Empty States**: When no data exists, the application explicitly displays:
   > *"No data available yet."*
4. **Isolated Test Fixtures**: Automated testing fixtures must run exclusively in isolated test databases and must never contaminate development or production data.
5. **Authenticated Administrator Bootstrap**: The initial system administrator is provisioned solely through an explicit, authenticated CLI command requiring genuine credentials.

---

## 2. Monorepo Structure

```
UniteCare/
├── apps/
│   ├── web/                     # Admin Web Application (Next.js + TypeScript + Tailwind CSS)
│   └── mobile/                  # Mobile Field Application (Expo + React Native + TypeScript)
├── backend/                     # Centralized API (FastAPI + Python + SQLAlchemy + Alembic)
│   ├── app/
│   │   ├── api/                 # API router and versioned endpoints (/api/v1)
│   │   ├── core/                # Configuration, security primitives, logging
│   │   ├── db/                  # Database engine, session lifecycle, Base model
│   │   └── modules/             # Modular monolith domain packages
│   │       ├── auth/            # Authentication & session token management
│   │       ├── users/           # User account lifecycle
│   │       ├── rbac/            # Roles, permissions, access guards
│   │       ├── organizations/   # NGOs & organization-scoped memberships
│   │       └── audit/           # Immutable audit logging engine
│   ├── alembic/                 # Database migrations
│   ├── requirements.txt         # Independent Python dependency specification
│   ├── pyproject.toml           # Tooling & metadata configuration
│   └── .env.example             # Backend environment template
├── docs/                        # Architecture, Data Policy, and Security specifications
│   ├── ARCHITECTURE.md
│   ├── DATA_POLICY.md
│   └── AUTHENTICATION_AND_ROLES.md
├── infrastructure/              # Local dev infrastructure and deployment manifests
│   └── README.md
├── docker-compose.yml           # PostgreSQL 16 service for local development
├── .gitignore                   # Comprehensive multi-stack ignore rules
├── .env.example                 # Global environment template
└── README.md                    # Root project documentation
```

---

## 3. Registration and Role Architecture

UniteCare employs a **Unified Role-Based Access Control (RBAC)** model with backend enforcement:

- **No Self-Assigned Privileges**: The registration endpoint rejects or ignores client-supplied roles.
- **Default Role**: Newly registered users are assigned a baseline `public_user` role.
- **Role Verification**: Registration alone does **not** grant `volunteer` or `donor` status:
  - `volunteer` access requires an approved NGO membership affiliation process.
  - `donor` onboarding requires explicit verification in a future phase.
- **Account Status**: Accounts default to `pending_verification` or `active` based on system activation policy. Suspended or deactivated accounts are instantly denied access on all endpoints.
- **Unified RBAC**: The system eliminates `is_superuser` column flags; system administrators are granted the `system_admin` role with explicit permissions.
- **Organization-Scoped Roles**: NGO roles (`admin`, `staff`, `volunteer`, `member`) are strictly isolated via `ngo_memberships` scoped to a specific `ngo_id`.

---

## 4. Authentication Architecture

For the initial prototype, authentication relies on:

- **Email & Password**: Secure password hashing using Argon2id / bcrypt.
- **Token Model**: Short-lived JWT Access Tokens (15-minute validity) for stateless authorization.
- **Persistent Sessions**: Cryptographically random 256-bit Refresh Tokens stored as SHA-256 hashes in the database.
- **Transactional Rotation**: Every `/refresh` operation atomically invalidates the old token and issues a new pair.
- **Token Family Reuse Detection**: Sessions track a `family_id`. If an already-consumed refresh token is re-submitted, the entire token family is immediately revoked to neutralize token theft.
- **Secure Storage**: Web uses secure/HttpOnly storage mechanisms; mobile uses `expo-secure-store` backed by Android Keystore / iOS Keychain.

*(Google OAuth and Phone OTP providers are deferred to Stage 7).*

---

## 5. Getting Started (Stage 1 Setup)

### Prerequisites
- **Python**: 3.11+ (Python 3.13 supported)
- **Node.js**: 20+ (Node 24 supported) with `npm` 10+
- **Docker**: Docker Desktop (optional, for local PostgreSQL container) or an accessible PostgreSQL 16 database.

### 1. Database Provisioning
Start the local PostgreSQL container:
```bash
docker compose up -d postgres
```
*(Or point `DATABASE_URL` in `backend/.env` to an existing PostgreSQL 16 instance).*

### 2. Backend Initialization
```bash
cd backend
python -m venv .venv
# On Windows Powershell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

---

## 6. Implementation Stages Roadmap

- [x] **Stage 1**: Repository & Workspace Scaffolding (Current)
- [ ] **Stage 2**: Backend Configuration, Database Connection, SQLAlchemy & Alembic
- [ ] **Stage 3**: Minimal Authentication & Session Foundation (Email/Password)
- [ ] **Stage 4**: Basic Backend Authorization & RBAC
- [ ] **Stage 5**: Admin Web Application Foundation (Next.js)
- [ ] **Stage 6**: Mobile Application Foundation (Expo / React Native)
- [ ] **Stage 7**: Additional Authentication Providers (Phone OTP & Google Sign-In)
