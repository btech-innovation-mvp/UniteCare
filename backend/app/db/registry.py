"""Centralized model registry for SQLAlchemy and Alembic.

Architecture & Model Registration Strategy:
- `Base` is defined in `app.db.base` without importing any domain models, preventing circular dependencies.
- All domain model modules created in Stage 3 and beyond must be imported into this registry module.
- Importing them here registers their table definitions with `Base.metadata`.
- `backend/alembic/env.py` imports `target_metadata` from this module, ensuring Alembic autogenerate
  discovers all domain entities without requiring dynamic filesystem scanning or fragile import hooks.
"""

from app.db.base import Base
from app.modules.audit import models as _audit_models  # noqa: F401
from app.modules.auth import models as _auth_models  # noqa: F401
from app.modules.rbac import models as _rbac_models  # noqa: F401
from app.modules.users import models as _users_models  # noqa: F401

# Target metadata consumed by Alembic migrations and database introspection
target_metadata = Base.metadata

__all__ = ["Base", "target_metadata"]
