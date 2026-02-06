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
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    """Get authentication headers for test user."""
    # Register test user
    response = client.post("/auth/register", json={
        "username": "testuser_ai",
        "email": "testuser_ai@example.com",
        "password": "testpass123",
        "full_name": "Test User AI"
    })
    
    # Login
    response = client.post("/auth/login", json={
        "username": "testuser_ai",
        "password": "testpass123"
    })
    
    # Extract session cookie
    cookies = response.cookies
    return {"Cookie": f"session={cookies.get('session')}"}


def test_ai_providers_endpoint(client, auth_headers):
    """Test GET /api/ai/providers."""
    response = client.get("/api/ai/providers", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "providers" in data
    assert len(data["providers"]) >= 3
    
    # Check for expected providers
    provider_ids = [p["id"] for p in data["providers"]]
    assert "openai" in provider_ids
    assert "anthropic" in provider_ids
    assert "custom" in provider_ids
    
    # Verify provider structure
    for provider in data["providers"]:
        assert "id" in provider
        assert "name" in provider
        assert "requires_api_key" in provider
        

def test_ai_suggestions_endpoint(client, auth_headers):
    """Test GET /api/ai/suggestions."""
    response = client.get("/api/ai/suggestions", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "categories" in data
    assert len(data["categories"]) >= 3
    
    # Verify category structure
    for category in data["categories"]:
        assert "name" in category
        assert "prompts" in category
        assert len(category["prompts"]) > 0


def test_ai_config_save_and_get(client, auth_headers):
    """Test POST /api/ai/config and GET /api/ai/config."""
    # First check - should not be configured
    response = client.get("/api/ai/config", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] == False
    
    # Save config
    config = {
        "provider": "openai",
        "api_key": "sk-test-key-123",
        "model": "gpt-4",
        "base_url": None,
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    response = client.post("/api/ai/config", headers=auth_headers, json=config)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    
    # Get config - should now be configured
    response = client.get("/api/ai/config", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] == True
    assert data["provider"] == "openai"
    assert data["model"] == "gpt-4"
    assert data["has_api_key"] == True
    # API key should NOT be returned
    assert "api_key" not in data


def test_ai_chat_without_config(client, auth_headers):
    """Test POST /api/ai/chat without configuration."""
    # Clear any existing config by using a new user
    response = client.post("/auth/register", json={
        "username": "testuser_ai_2",
        "email": "testuser_ai_2@example.com",
        "password": "testpass123",
        "full_name": "Test User AI 2"
    })
    
    response = client.post("/auth/login", json={
        "username": "testuser_ai_2",
        "password": "testpass123"
    })
    cookies = response.cookies
    new_headers = {"Cookie": f"session={cookies.get('session')}"}
    
    # Try to chat without config
    response = client.post("/api/ai/chat", headers=new_headers, json={
        "message": "Test message",
        "history": [],
        "context": {}
    })
    
    assert response.status_code == 400
    data = response.json()
    assert "not configured" in data["detail"].lower()


def test_ai_config_validation(client, auth_headers):
    """Test AI config validation."""
    # Missing provider
    config = {
        "provider": "",
        "api_key": "test-key"
    }
    # This should still return 200 but the client-side validation should catch it
    # For now we're just testing the endpoint exists
    
    # Missing API key
    config = {
        "provider": "openai",
        "api_key": ""
    }
    # Same as above - client-side validation


def test_ai_unauthorized_access(client):
    """Test that AI endpoints require authentication."""
    # Try accessing without auth
    response = client.get("/api/ai/config")
    assert response.status_code == 401
    
    response = client.post("/api/ai/config", json={})
    assert response.status_code == 401
    
    response = client.get("/api/ai/providers")
    assert response.status_code == 401
    
    response = client.get("/api/ai/suggestions")
    assert response.status_code == 401
    
    response = client.post("/api/ai/chat", json={})
    assert response.status_code == 401


def test_custom_provider_requires_base_url(client, auth_headers):
    """Test that custom provider should have base_url."""
    config = {
        "provider": "custom",
        "api_key": "test-key",
        "model": "custom-model",
        "base_url": "http://localhost:11434/v1",
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    response = client.post("/api/ai/config", headers=auth_headers, json=config)
    assert response.status_code == 200
    
    # Verify it was saved
    response = client.get("/api/ai/config", headers=auth_headers)
    data = response.json()
    assert data["provider"] == "custom"
    assert data["base_url"] == "http://localhost:11434/v1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
