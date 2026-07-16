"""
Tests for at-rest encryption of AI provider keys and the admin-password
lifecycle fix.

Covers:
  * crypto round-trip, ciphertext opacity, graceful failure, keyfile perms
  * AICredential storing ciphertext while exposing plaintext through the ORM
  * a stored value that can't be decrypted reading back as None (not a crash)
  * create_or_update_admin preserving the password on plain restarts and
    rotating only on explicit request
"""

import os
import sqlite3
import stat

import pytest

from medaudit.web.ai import crypto


@pytest.fixture
def isolated_keyfile(tmp_path, monkeypatch):
    """Point the crypto module at a throwaway keyfile and reset its cache."""
    keyfile = tmp_path / ".secret_key"
    monkeypatch.setattr(crypto, "_keyfile_path", lambda: keyfile)
    crypto._reset_for_tests()
    yield keyfile
    crypto._reset_for_tests()


# --------------------------------------------------------------------------- #
# crypto module
# --------------------------------------------------------------------------- #

def test_round_trip(isolated_keyfile):
    secret = "FAKEKEY-not-a-real-credential-round-trip"
    token = crypto.encrypt(secret)
    assert token != secret               # not stored in the clear
    assert crypto.decrypt(token) == secret


def test_keyfile_created_with_0600(isolated_keyfile):
    crypto.encrypt("anything")           # forces key creation
    assert isolated_keyfile.exists()
    mode = stat.S_IMODE(os.stat(isolated_keyfile).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_decrypt_garbage_returns_none(isolated_keyfile):
    assert crypto.decrypt("not-a-valid-token") is None
    assert crypto.decrypt("") is None


def test_none_passthrough(isolated_keyfile):
    assert crypto.encrypt(None) is None
    assert crypto.decrypt(None) is None


def test_wrong_key_cannot_decrypt(isolated_keyfile, tmp_path, monkeypatch):
    """A token encrypted under one key is unreadable after the key rotates."""
    token = crypto.encrypt("secret")
    # Rotate: new keyfile location, fresh cipher.
    monkeypatch.setattr(crypto, "_keyfile_path", lambda: tmp_path / ".secret_key_2")
    crypto._reset_for_tests()
    assert crypto.decrypt(token) is None  # graceful, not an exception


# --------------------------------------------------------------------------- #
# AICredential encryption at rest
# --------------------------------------------------------------------------- #

def _make_db(tmp_path):
    from medaudit.web.database import DatabaseManager
    mgr = DatabaseManager(db_path=tmp_path / "test.db")
    mgr.create_tables()
    return mgr


def test_credential_encrypted_in_db_but_plaintext_via_orm(isolated_keyfile, tmp_path):
    from medaudit.web.database import AICredential

    mgr = _make_db(tmp_path)
    session = mgr.get_session()
    try:
        cred = AICredential(
            project_id="proj-1", provider="openai",
            api_key="FAKEKEY-not-a-real-credential-123456", default_model="gpt-4o",
        )
        session.add(cred)
        session.commit()
        cred_id = cred.id
    finally:
        session.close()

    # ORM read decrypts transparently.
    session = mgr.get_session()
    try:
        loaded = session.query(AICredential).filter_by(id=cred_id).one()
        assert loaded.api_key == "FAKEKEY-not-a-real-credential-123456"
    finally:
        session.close()

    # Raw DB read shows ciphertext, never the plaintext.
    raw = sqlite3.connect(str(tmp_path / "test.db"))
    try:
        stored = raw.execute(
            "SELECT api_key FROM ai_credentials WHERE id=?", (cred_id,)
        ).fetchone()[0]
    finally:
        raw.close()
    assert "FAKEKEY-not-a-real-credential-123456" not in stored
    assert crypto.decrypt(stored) == "FAKEKEY-not-a-real-credential-123456"


def test_undecryptable_credential_reads_as_none(isolated_keyfile, tmp_path):
    from medaudit.web.database import AICredential

    mgr = _make_db(tmp_path)
    session = mgr.get_session()
    try:
        cred = AICredential(project_id="p", provider="openai", api_key="FAKEKEY-x")
        session.add(cred)
        session.commit()
        cred_id = cred.id
    finally:
        session.close()

    # Corrupt the stored ciphertext directly.
    raw = sqlite3.connect(str(tmp_path / "test.db"))
    try:
        raw.execute("UPDATE ai_credentials SET api_key='garbage' WHERE id=?", (cred_id,))
        raw.commit()
    finally:
        raw.close()

    session = mgr.get_session()
    try:
        loaded = session.query(AICredential).filter_by(id=cred_id).one()
        assert loaded.api_key is None                       # graceful
        masked = loaded.to_dict(include_keys=True)["api_key_masked"]
        assert "unavailable" in masked                      # no crash on None
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# admin password lifecycle
# --------------------------------------------------------------------------- #

def test_password_preserved_on_plain_restart(tmp_path):
    mgr = _make_db(tmp_path)
    session = mgr.get_session()
    try:
        # First run: random password generated.
        admin1, pw1 = mgr.create_or_update_admin(session)
        assert pw1 is not None
        # "Restart" with no flags: password unchanged, nothing new to display.
        admin2, pw2 = mgr.create_or_update_admin(session)
        assert pw2 is None
        assert admin2.verify_password(pw1)                  # old password still valid
    finally:
        session.close()


def test_explicit_password_and_rotation(tmp_path):
    mgr = _make_db(tmp_path)
    session = mgr.get_session()
    try:
        _, pw1 = mgr.create_or_update_admin(session, password="FirstPass123")  # gitleaks:allow (test fixture)
        assert pw1 == "FirstPass123"

        # Explicit new password on an existing admin.
        admin, pw2 = mgr.create_or_update_admin(session, password="SecondPass456")  # gitleaks:allow (test fixture)
        assert pw2 == "SecondPass456"
        assert admin.verify_password("SecondPass456")
        assert not admin.verify_password("FirstPass123")

        # generate_random rotates to a fresh random password.
        admin, pw3 = mgr.create_or_update_admin(session, generate_random=True)
        assert pw3 is not None and pw3 != pw2
        assert admin.verify_password(pw3)
    finally:
        session.close()
