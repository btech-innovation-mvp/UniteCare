# UniteCare Infrastructure & Local Development Services

This directory contains specifications and manifests for local development and deployment infrastructure.

## 1. Local PostgreSQL Service

A standard Docker Compose configuration is provided at the repository root (`docker-compose.yml`):

```bash
# Start PostgreSQL in background
docker compose up -d postgres

# Stop PostgreSQL
docker compose down

# Check container health status
docker compose ps
```

### Storage Persistence
PostgreSQL data files are persisted in the named Docker volume `unitecare_pgdata`. 
Volume persistence ensures data remains intact across container restarts without risking schema or data loss.

### Non-Negotiable Data Policy Compliance
The database image does **not** include initialization seed scripts, dummy data, or mock user inserts. The database schema must be initialized exclusively through Alembic migrations.

## 2. Network Mapping

| Service | Container Port | Host Port | Network |
| :--- | :--- | :--- | :--- |
| **PostgreSQL** | `5432` | `5432` | `unitecare_network` |
| **FastAPI Backend** | `8000` | `8000` | Host Network / Bridge |
| **Next.js Admin** | `3000` | `3000` | Host Network |
| **Expo Metro Bundler** | `8081` | `8081` | Host Network |
