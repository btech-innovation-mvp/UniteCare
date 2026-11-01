"""Database session management and lifecycle."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

# Engine setup (pool configuration ready for Stage 2)
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding database session per request.

    Explicitly rolls back any uncommitted changes if an unhandled exception occurs
    within the request context, and guarantees connection return to pool in finally.
    Does NOT commit automatically; transaction commitment is the caller's responsibility.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
