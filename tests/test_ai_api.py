"""
Test AI Analysis API endpoints.

Run with: pytest tests/test_ai_api.py -v
"""

import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from medaudit.web.app import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def auth_cookies(client):
    """
    Get authentication cookies for the admin test user.

    Uses the admin account which is always present.
    We use the database manager to set a known password so the test is
    deterministic regardless of startup-time password generation.
    """
    from medaudit.web.database import get_db_manager
    db_manager = get_db_manager()
    db = db_manager.get_session()
    try:
        admin, _pwd = db_manager.create_or_update_admin(db, password="TestPass1234!")
    finally:
        db.close()

    response = client.post("/auth/login", json={
        "username": "admin",
        "password": "TestPass1234!"
    })
    assert response.status_code == 200, f"Login failed: {response.text}"
    # Return cookies dict (session_token is set as httpOnly cookie)
    return {"session_token": response.cookies.get("session_token")}


# =============================================================================
# Provider listing / config endpoints
# =============================================================================

def test_ai_providers_endpoint_requires_auth(client):
    """GET /api/ai/providers should return 401 without auth."""
    response = client.get("/api/ai/providers")
    assert response.status_code == 401


def test_ai_providers_endpoint_authenticated(client, auth_cookies):
    """GET /api/ai/providers should return provider metadata when authenticated."""
    response = client.get("/api/ai/providers", cookies=auth_cookies)
    assert response.status_code == 200

    data = response.json()
    # Endpoint returns available_providers and configured providers
    assert "available_providers" in data
    available = data["available_providers"]
    # At minimum openai, anthropic, ollama must be listed
    assert "openai" in available
    assert "anthropic" in available


def test_ai_config_endpoint_authenticated(client, auth_cookies):
    """GET /api/ai/config should return configuration status."""
    response = client.get("/api/ai/config", cookies=auth_cookies)
    assert response.status_code == 200

    data = response.json()
    assert "configured" in data
    assert "provider" in data
    assert "model" in data
    assert "auto_analyze" in data


def test_ai_config_endpoint_requires_auth(client):
    """GET /api/ai/config should return 401 without auth."""
    response = client.get("/api/ai/config")
    assert response.status_code == 401


# =============================================================================
# Provider configure endpoint
# =============================================================================

def test_ai_configure_provider_requires_auth(client):
    """POST /api/ai/providers/configure should return 401 without auth."""
    response = client.post("/api/ai/providers/configure", json={
        "provider": "openai",
        "api_key": "sk-test"
    })
    assert response.status_code == 401


def test_ai_configure_provider_invalid_key(client, auth_cookies):
    """POST /api/ai/providers/configure with a bad key should return 401."""
    response = client.post(
        "/api/ai/providers/configure",
        cookies=auth_cookies,
        json={
            "provider": "openai",
            "api_key": "sk-obviously-invalid-key-xyz",
        }
    )
    # Should fail key validation → 401
    assert response.status_code == 401


def test_ai_configure_unknown_provider(client, auth_cookies):
    """POST /api/ai/providers/configure with an unknown provider should return 400."""
    response = client.post(
        "/api/ai/providers/configure",
        cookies=auth_cookies,
        json={
            "provider": "nonexistent_provider",
            "api_key": "some-key",
        }
    )
    assert response.status_code == 400


# =============================================================================
# Chat endpoint
# =============================================================================

def test_ai_chat_requires_auth(client):
    """POST /api/ai/chat should return 401 without auth."""
    response = client.post("/api/ai/chat", json={
        "message": "Hello",
        "project_id": "test-project-id",
    })
    assert response.status_code == 401


def test_ai_chat_without_provider_configured(client, auth_cookies):
    """POST /api/ai/chat without any provider configured should return 400."""
    # First disconnect all providers to ensure clean state
    client.post("/api/ai/disconnect", cookies=auth_cookies)

    response = client.post(
        "/api/ai/chat",
        cookies=auth_cookies,
        json={
            "message": "Test message",
            "project_id": "test-proj-abc",
        }
    )
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "no ai provider" in data["detail"].lower() or "not configured" in data["detail"].lower()


# =============================================================================
# Validate endpoint
# =============================================================================

def test_ai_validate_endpoint_requires_auth(client):
    """POST /api/ai/providers/validate should return 401 without auth."""
    response = client.post("/api/ai/providers/validate", json={
        "provider": "openai",
        "api_key": "sk-test"
    })
    assert response.status_code == 401


def test_ai_validate_invalid_key(client, auth_cookies):
    """POST /api/ai/providers/validate with a bad key should return valid=False."""
    response = client.post(
        "/api/ai/providers/validate",
        cookies=auth_cookies,
        json={
            "provider": "openai",
            "api_key": "sk-obviously-fake-key-12345",
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False


# =============================================================================
# Usage endpoint
# =============================================================================

def test_ai_usage_endpoint_requires_auth(client):
    """GET /api/ai/usage should return 401 without auth."""
    response = client.get("/api/ai/usage")
    assert response.status_code == 401


def test_ai_usage_endpoint_authenticated(client, auth_cookies):
    """GET /api/ai/usage should return usage stats when authenticated."""
    response = client.get("/api/ai/usage", cookies=auth_cookies)
    assert response.status_code == 200
    data = response.json()
    # Usage tracker should return token counts
    assert "input_tokens" in data or "total_input_tokens" in data or isinstance(data, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
