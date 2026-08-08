"""
Tests for HTTP-to-MLLP Proxy API parameters and functionality.
"""

import sys
import pytest
from fastapi.testclient import TestClient

from medaudit.web.app import app
from medaudit.web.database import DatabaseManager, User
from medaudit.web.auth import get_current_user
from medaudit.web.proxy_api import active_proxies, ProxyStartRequest


@pytest.fixture
def client():
    """Create test client."""
    active_proxies.clear()
    c = TestClient(app, raise_server_exceptions=False)
    yield c
    for port, info in list(active_proxies.items()):
        try:
            proc = info["process"] if isinstance(info, dict) else info
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            pass
    active_proxies.clear()


@pytest.fixture
def auth_cookies(client):
    """Get authentication cookies for the admin test user."""
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
    return {"session_token": response.cookies.get("session_token")}


def test_proxy_start_request_model():
    """Verify default values and custom input for ProxyStartRequest."""
    req = ProxyStartRequest(proxy_port=3000)
    assert req.proxy_host == "0.0.0.0"
    assert req.proxy_port == 3000
    assert req.hl7_host == "localhost"
    assert req.hl7_port == 2575

    custom_req = ProxyStartRequest(
        proxy_host="127.0.0.1",
        proxy_port=3001,
        hl7_host="192.168.1.100",
        hl7_port=2576
    )
    assert custom_req.proxy_host == "127.0.0.1"
    assert custom_req.proxy_port == 3001
    assert custom_req.hl7_host == "192.168.1.100"
    assert custom_req.hl7_port == 2576


def test_proxy_start_stop_lifecycle(client, auth_cookies):
    """Test starting and stopping proxy via API with custom host parameters."""
    start_resp = client.post(
        "/api/proxy/start",
        cookies=auth_cookies,
        json={
            "proxy_host": "127.0.0.1",
            "proxy_port": 3999,
            "hl7_host": "127.0.0.1",
            "hl7_port": 2575
        }
    )
    assert start_resp.status_code == 200, f"Start failed: {start_resp.text}"
    start_data = start_resp.json()
    assert start_data["success"] is True
    proxy_info = start_data["proxy"]
    assert proxy_info["host"] == "127.0.0.1"
    assert proxy_info["port"] == 3999
    assert proxy_info["hl7_host"] == "127.0.0.1"
    assert proxy_info["hl7_port"] == 2575
    assert proxy_info["status"] == "running"

    # Status check
    status_resp = client.get("/api/proxy/status?proxy_port=3999", cookies=auth_cookies)
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["success"] is True
    assert status_data["proxy"]["status"] == "running"
    assert status_data["proxy"]["host"] == "127.0.0.1"

    # List check
    list_resp = client.get("/api/proxy/list", cookies=auth_cookies)
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["success"] is True
    matching = [p for p in list_data["proxies"] if p["port"] == 3999]
    assert len(matching) == 1
    assert matching[0]["host"] == "127.0.0.1"

    # Stop proxy
    stop_resp = client.post("/api/proxy/stop", cookies=auth_cookies, json={"proxy_port": 3999})
    assert stop_resp.status_code == 200
    assert stop_resp.json()["success"] is True

    # Confirm stopped status
    post_stop_status = client.get("/api/proxy/status?proxy_port=3999", cookies=auth_cookies)
    assert post_stop_status.json()["proxy"]["status"] == "stopped"
