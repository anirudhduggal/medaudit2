"""
Pytest configuration and shared fixtures for Medaudit 2.0 tests

This file is automatically discovered by pytest and used to configure
test discovery, fixtures, and other test settings.
"""

import sys
from pathlib import Path

# Add the workspace root to sys.path for imports
WORKSPACE_ROOT = Path(__file__).parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "pcap: mark test as using PCAP files"
    )
    config.addinivalue_line(
        "markers", "pii: mark test as testing PII detection"
    )


# Import and make available any pytest fixtures needed across tests
# Example: shared HL7 server fixtures, mock analyzers, etc.

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolate_database(tmp_path_factory):
    """
    Point ALL database access at a throwaway SQLite file for the whole test
    session, so tests never touch the real medaudit.db.

    Both get_db_manager() (used directly by tests) and the get_db() FastAPI
    dependency (used by the app under TestClient) resolve the module-level
    _db_manager singleton at call time, so overriding it here isolates both.
    Without this, auth tests call create_or_update_admin() against the real DB
    and reset the operator's admin password (and leave junk projects behind).
    """
    from medaudit.web import database

    tmp_db = tmp_path_factory.mktemp("medaudit_testdb") / "test.db"
    test_manager = database.DatabaseManager(db_path=tmp_db)
    test_manager.create_tables()

    original = database._db_manager
    database._db_manager = test_manager
    try:
        yield test_manager
    finally:
        database._db_manager = original
        try:
            test_manager.engine.dispose()
        except Exception:
            pass


@pytest.fixture(scope="session")
def workspace_root():
    """Return the workspace root directory."""
    return WORKSPACE_ROOT


@pytest.fixture(scope="session")
def test_data_dir():
    """Return the test data directory."""
    return WORKSPACE_ROOT / "medaudit" / "testFiles"


@pytest.fixture(scope="session")
def sample_pcap():
    """Return path to sample PCAP file."""
    pcap = WORKSPACE_ROOT / "medaudit" / "testFiles" / "hl7_v2_unencrypted_synthetic.pcap"
    if not pcap.exists():
        pytest.skip(f"Sample PCAP not found: {pcap}")
    return pcap
