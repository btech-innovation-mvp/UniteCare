"""Tests for FastAPI startup, foundational liveness, and database readiness endpoints."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.db.session import get_db
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Verify root endpoint responds with basic service status and documentation link."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "UniteCare API"
    assert data["version"] == "0.1.0"
    assert "docs" in data


def test_liveness_check_endpoint():
    """Verify /api/v1/health functions as a lightweight liveness probe."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "unitecare-api"
    assert data["version"] == "0.1.0"


def test_readiness_check_endpoint_success():
    """Verify /api/v1/health/ready returns 200 when database connectivity succeeds."""
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["service"] == "unitecare-api"


def test_readiness_check_endpoint_database_failure():
    """Verify /api/v1/health/ready returns 503 Service Unavailable when database fails.

    Ensures no connection strings, credentials, or internal exception traces are leaked.
    """
    mock_db = MagicMock()
    mock_db.execute.side_effect = OperationalError("connection failure", None, None)

    # Override get_db dependency to simulate database failure safely
    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unready"
        assert data["database"] == "unavailable"
        assert data["service"] == "unitecare-api"
        # Ensure no sensitive database details or traces are in the response
        assert "password" not in response.text
        assert "Traceback" not in response.text
    finally:
        app.dependency_overrides.clear()
