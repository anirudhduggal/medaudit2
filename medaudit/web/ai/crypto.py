"""
Local at-rest encryption for stored secrets (currently: AI provider API keys).

Design
------
A random data-encryption key (DEK) is generated on first use and written to a
sidecar keyfile (``medaudit/data/.secret_key``) with ``0600`` permissions. The
DEK is deliberately **independent of the admin login password**, because the
admin password is regenerated on demand (and historically on every launch), so
binding encryption to it would orphan stored credentials on rotation.

What this protects against
--------------------------
The realistic passive-exposure paths for a local pentest tool:
  * the SQLite database being committed to git,
  * synced to a cloud drive,
  * swept into a backup, or
  * shared for support.
In all of those the ``.db`` travels *without* the adjacent keyfile and is inert.

What this does NOT protect against
----------------------------------
An attacker who can read the whole data directory or process memory. For a
single-operator local tool that is out of scope; encrypting here is about not
leaking keys through the database file alone.

All functions degrade gracefully: if the ``cryptography`` package is missing or
a value cannot be decrypted (e.g. keyfile rotated/lost), ``decrypt`` returns
``None`` rather than raising, so callers can treat the credential as
unconfigured and prompt for re-entry.
"""

import logging
import os
import stat
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_KEYFILE_NAME = ".secret_key"
_cipher = None            # cached Fernet instance (None until initialized)
_cipher_lock = threading.Lock()


def _keyfile_path() -> Path:
    from medaudit.utils import get_data_dir
    return get_data_dir() / _KEYFILE_NAME


def _load_or_create_key() -> Optional[bytes]:
    """
    Return the DEK bytes, creating (and persisting at 0600) one if absent.
    Returns None if the key cannot be established.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.warning(
            "cryptography package not installed; API keys will not be "
            "encrypted at rest. Run: pip install cryptography"
        )
        return None

    path = _keyfile_path()
    try:
        if path.exists():
            key = path.read_bytes().strip()
            if key:
                return key
            logger.warning("Secret keyfile %s is empty; regenerating", path)

        # Generate and persist a new key with restrictive permissions.
        key = Fernet.generate_key()
        # Create the file with 0600 from the outset (avoid a readable window).
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        # Best-effort tighten in case umask/OS ignored the create mode.
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.info("Generated new secret keyfile at %s (0600)", path)
        return key
    except OSError as e:
        logger.error("Could not read/create secret keyfile %s: %s", path, e)
        return None


def _get_cipher():
    """Lazily build and cache the Fernet cipher. Returns None if unavailable."""
    global _cipher
    if _cipher is not None:
        return _cipher
    with _cipher_lock:
        if _cipher is not None:
            return _cipher
        key = _load_or_create_key()
        if key is None:
            return None
        try:
            from cryptography.fernet import Fernet
            _cipher = Fernet(key)
        except Exception as e:  # invalid key material, etc.
            logger.error("Failed to initialize cipher: %s", e)
            return None
        return _cipher


def is_available() -> bool:
    """True if encryption is operational (package present and key established)."""
    return _get_cipher() is not None


def encrypt(plaintext: Optional[str]) -> Optional[str]:
    """
    Encrypt a string for storage. Returns a token string.

    If encryption is unavailable the plaintext is returned unchanged so the
    feature still functions (with a logged warning) rather than losing data.
    """
    if plaintext is None:
        return None
    cipher = _get_cipher()
    if cipher is None:
        return plaintext  # store as-is; warning already logged
    return cipher.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: Optional[str]) -> Optional[str]:
    """
    Decrypt a stored token. Returns the plaintext, or None if it cannot be
    decrypted (missing cipher, wrong/rotated key, or corrupt/legacy value).

    Callers should treat a None result as "credential unavailable, re-enter".
    """
    if token is None:
        return None
    cipher = _get_cipher()
    if cipher is None:
        return None
    try:
        from cryptography.fernet import InvalidToken
        return cipher.decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        # InvalidToken, non-ascii/corrupt data, or plaintext from a pre-encryption DB.
        logger.warning("Could not decrypt a stored secret; treating as unavailable")
        return None


def _reset_for_tests():
    """Clear the cached cipher (test helper only)."""
    global _cipher
    with _cipher_lock:
        _cipher = None
