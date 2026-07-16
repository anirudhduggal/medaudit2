"""
SQLite storage for the demo hospital.

Holds the "patient worklist" that the MLLP feed populates and the clinical
viewer renders. Also keeps a raw message log for the detail view.
"""

import sqlite3
import threading
from pathlib import Path

# Single-file DB inside the container; wiped/reseeded on container rebuild.
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "hospital.db"

_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """Per-thread connection (the MLLP server and Flask run in different threads)."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _local.conn = conn
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS patients (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mrn        TEXT,
            family     TEXT,
            given      TEXT,
            dob        TEXT,
            sex        TEXT,
            ssn        TEXT,
            last_order TEXT,
            last_result TEXT,
            msg_type   TEXT,
            raw_hl7    TEXT,
            received_at TEXT
        );
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT,
            msg_type    TEXT,
            raw_hl7     TEXT,
            ack_code    TEXT,
            note        TEXT,
            received_at TEXT
        );
        """
    )
    conn.commit()


def log_message(source: str, msg_type: str, raw_hl7: str, ack_code: str, note: str, ts: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO messages (source, msg_type, raw_hl7, ack_code, note, received_at) "
        "VALUES (?,?,?,?,?,?)",
        (source, msg_type, raw_hl7, ack_code, note, ts),
    )
    conn.commit()
