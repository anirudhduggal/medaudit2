"""
Tests for the fuzzer blast-radius guard.

Three layers:
  1. Unit tests for medaudit.fuzzer.safety (loopback detection, authorization,
     volume/rate clamping).
  2. Engine-level enforcement: run_fuzzing_job refuses an unauthorized remote
     target and returns a clean "refused" status (no crash, no traffic sent).
  3. End-to-end: a real localhost fuzz campaign against the mock HL7 server,
     proving the whole chain (config -> generate -> MLLP send -> ACK -> findings
     -> logs) still works after the guard changes.
  4. API-level: the web endpoint 400s on an unconfirmed remote target and
     accepts a confirmed one (also documents that the endpoint takes a JSON
     body, not query params).
"""

import socket
import threading
import time

import pytest

from medaudit.fuzzer import safety
from medaudit.fuzzer.engine import run_fuzzing_job


BASE_MESSAGE = "MSH|^~\\&|MEDAUDIT|TEST|TARGET|DEV|20200101||ADT^A01|1|P|2.5\rPID|1||X||Y^Z||19800101|M"


def _field_rule():
    return {"name": "r1", "target": "field", "segment": "PID",
            "field_index": 3, "strategy": "sql", "iterations": 2}


# --------------------------------------------------------------------------- #
# 1. safety unit tests
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.0.0.5", "::1", "LOCALHOST"])
def test_loopback_detected(host):
    assert safety.is_loopback_target(host) is True


@pytest.mark.parametrize("host", ["10.0.0.5", "192.168.1.10", "example.com", "device.hospital.local", ""])
def test_non_loopback_detected(host):
    assert safety.is_loopback_target(host) is False


def test_check_authorization_allows_loopback():
    # Should not raise even when not authorized.
    safety.check_authorization("127.0.0.1", authorized=False)


def test_check_authorization_blocks_remote_unauthorized():
    with pytest.raises(safety.TargetNotAuthorized):
        safety.check_authorization("10.0.0.5", authorized=False)


def test_check_authorization_allows_remote_when_authorized():
    safety.check_authorization("10.0.0.5", authorized=True)


def test_apply_limits_caps_volume(monkeypatch):
    monkeypatch.setattr(safety, "MAX_REQUESTS_CEILING", 100)
    max_req, delay, notes = safety.apply_limits(10_000, 100, "localhost")
    assert max_req == 100
    assert any("max_requests" in n for n in notes)


def test_apply_limits_rate_floor_remote_only(monkeypatch):
    monkeypatch.setattr(safety, "MIN_REMOTE_DELAY_MS", 20)
    # Remote target: delay floored.
    _, delay_remote, notes = safety.apply_limits(10, 0, "10.0.0.5")
    assert delay_remote == 20 and any("delay_ms" in n for n in notes)
    # Loopback: delay untouched.
    _, delay_local, _ = safety.apply_limits(10, 0, "localhost")
    assert delay_local == 0


# --------------------------------------------------------------------------- #
# 2. engine refuses unauthorized remote target (no traffic sent)
# --------------------------------------------------------------------------- #

def test_engine_refuses_unauthorized_remote():
    config = {
        "name": "should-not-run",
        "target_host": "10.255.255.1",   # non-loopback, unreachable
        "target_port": 2575,
        "base_message": BASE_MESSAGE,
        "rules": [_field_rule()],
        "max_requests": 5,
    }
    result = run_fuzzing_job("refuse-test", config, authorized=False)
    assert result["status"] == "refused"
    assert result["total_requests"] == 0
    assert "authorization" in result["error"].lower()


# --------------------------------------------------------------------------- #
# 3. end-to-end localhost campaign against the real mock server
# --------------------------------------------------------------------------- #

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def mock_hl7_server(tmp_path):
    from medaudit.hl7server.hl7_mock_server import HL7Server
    port = _free_port()
    server = HL7Server(host="127.0.0.1", port=port, log_dir=str(tmp_path / "srv"),
                       verbose=False)
    server.start()
    # Give the accept loop a moment to come up.
    time.sleep(0.3)
    yield "127.0.0.1", port
    # NOTE: HL7Server.stop() can hang on the MessageLogger write_lock (a
    # pre-existing concurrency bug in the mock server). Bound teardown so the
    # test suite never blocks; the server's threads are daemon and die at exit.
    stopper = threading.Thread(target=server.stop, daemon=True)
    stopper.start()
    stopper.join(2)


def test_end_to_end_localhost_fuzz(mock_hl7_server, tmp_path):
    host, port = mock_hl7_server
    config = {
        "name": "e2e",
        "target_host": host,
        "target_port": port,
        "use_tls": False,
        "base_message": BASE_MESSAGE,
        "rules": [_field_rule()],   # 2 SQL mutations
        "delay_ms": 0,
        "timeout_seconds": 1,
        "max_requests": 10,
    }
    result = run_fuzzing_job("e2e-test", config, authorized=False)  # loopback: no auth needed
    assert result["status"] == "completed", result
    assert result["total_requests"] >= 1
    # The mock server ACKs, so requests should succeed (not error out).
    assert result["successful"] >= 1


def test_volume_cap_streams_without_materializing(mock_hl7_server, monkeypatch):
    """A huge max_requests is clamped to the ceiling rather than exhausting memory."""
    monkeypatch.setattr(safety, "MAX_REQUESTS_CEILING", 3)
    host, port = mock_hl7_server
    config = {
        "name": "cap",
        "target_host": host,
        "target_port": port,
        "base_message": BASE_MESSAGE,
        "rules": [{"name": "many", "target": "field", "segment": "PID",
                   "field_index": 3, "strategy": "overflow", "iterations": 1000}],
        "delay_ms": 0,
        "timeout_seconds": 1,
        "max_requests": 1000,
    }
    result = run_fuzzing_job("cap-test", config, authorized=False)
    assert result["status"] == "completed"
    assert result["total_requests"] <= 3


# --------------------------------------------------------------------------- #
# 4. API-level guard (JSON body, not query params)
# --------------------------------------------------------------------------- #

@pytest.fixture
def api_client():
    from fastapi.testclient import TestClient
    from medaudit.web.app import app
    from medaudit.web.database import get_db_manager
    client = TestClient(app, raise_server_exceptions=False)
    dbm = get_db_manager()
    db = dbm.get_session()
    dbm.create_or_update_admin(db, password="TestPass1234!")
    db.close()
    r = client.post("/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200
    cookies = {"session_token": r.cookies.get("session_token")}
    import uuid
    r = client.post("/api/projects", json={"name": f"guard-{uuid.uuid4().hex[:8]}", "description": "x"}, cookies=cookies)
    body = r.json()
    pid = body.get("project", {}).get("id") or body.get("id")
    return client, cookies, pid


def _yaml_config(host):
    return (
        "name: t\n"
        f"target_host: {host}\n"
        "target_port: 2575\n"
        "base_message: |\n"
        "  MSH|^~\\&|A|B|C|D|20200101||ADT^A01|1|P|2.5\n"
        "rules:\n"
        "  - name: r1\n"
        "    target: field\n"
        "    segment: MSH\n"
        "    field_index: 3\n"
        "    strategy: sql\n"
        "    iterations: 1\n"
    )


def test_api_remote_target_requires_confirmation(api_client):
    client, cookies, pid = api_client
    r = client.post(
        f"/api/fuzzer/projects/{pid}/jobs",
        json={"name": "j", "config_format": "yaml", "config_content": _yaml_config("10.0.0.5")},
        cookies=cookies,
    )
    assert r.status_code == 400
    assert "confirm_target" in r.json()["detail"]


def test_api_remote_target_with_confirmation(api_client):
    client, cookies, pid = api_client
    r = client.post(
        f"/api/fuzzer/projects/{pid}/jobs",
        json={"name": "j", "config_format": "yaml",
              "config_content": _yaml_config("10.0.0.5"), "confirm_target": True},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True


def test_api_localhost_no_confirmation_needed(api_client):
    client, cookies, pid = api_client
    r = client.post(
        f"/api/fuzzer/projects/{pid}/jobs",
        json={"name": "j", "config_format": "yaml", "config_content": _yaml_config("localhost")},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
