"""API v1 Central Router."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.auth import router as auth_router
from app.db.session import get_db

api_router = APIRouter()
api_router.include_router(auth_router)


@api_router.get("/health", tags=["system"])
def health_check():
    """Foundational liveness probe returning process status."""
    return {
        "status": "healthy",
        "service": "unitecare-api",
        "version": "0.1.0",
    }


@api_router.get("/health/ready", tags=["system"])
def readiness_check(db: Annotated[Session, Depends(get_db)]):
    """Readiness probe verifying infrastructure and database reachability.

    Executes a minimal SELECT 1 ping. Returns 503 Service Unavailable if the
    database cannot be reached, without exposing connection strings or tracebacks.
    """
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "service": "unitecare-api",
            "database": "connected",
        }
    except (SQLAlchemyError, OSError):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unready",
                "service": "unitecare-api",
                "database": "unavailable",
            },
        )
