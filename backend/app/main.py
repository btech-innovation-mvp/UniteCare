"""FastAPI Application Factory for UniteCare Centralized Backend."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context for startup and shutdown management."""
    # Startup: verification of environment settings
    yield
    # Shutdown: clean up any resources if needed


def create_application() -> FastAPI:
    """Factory function to build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.APP_NAME,
        version="0.1.0",
        description="Centralized backend for UniteCare social-impact coordination platform.",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url=f"{settings.API_V1_STR}/docs",
        redoc_url=f"{settings.API_V1_STR}/redoc",
        lifespan=lifespan,
    )

    # Set up CORS middleware
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.BACKEND_CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )

    # Mount API v1 router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    @app.get("/", tags=["system"])
    def root():
        """Root endpoint returning basic service status."""
        return {
            "name": settings.APP_NAME,
            "version": "0.1.0",
            "environment": settings.ENVIRONMENT,
            "docs": f"{settings.API_V1_STR}/docs",
        }

    return app


app = create_application()
