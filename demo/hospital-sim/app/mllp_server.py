"""
Deliberately vulnerable MLLP (HL7) listener for the demo hospital.

⚠️  This code contains INTENTIONAL security flaws for authorized security-testing
    demonstrations only. Never deploy it on a real network or with real PHI.

Planted weaknesses (each maps to a medaudit2 capability):
  1. Plaintext transport (no TLS)          -> PCAP capture + PII/encryption findings
  2. SQL injection in the PID-3 MRN lookup -> fuzzer SQLi payloads reflected as errors
  3. No bound on field size                -> oversized input drops the connection (crash)
  4. Patient name stored verbatim          -> stored XSS rendered later by the viewer
"""

import logging
import socket
import sqlite3
import threading
from datetime import datetime, timezone

from . import db
from .hl7_parse import (
    strip_mllp,
    wrap_mllp,
    parse_segments,
    extract_patient,
    build_ack,
)

logger = logging.getLogger("hospital.mllp")

# Any field longer than this "overflows the device buffer" and crashes the
# connection handler -- a stand-in for fragile embedded parsers.
MAX_FIELD_LEN = 8192


class VulnerableMLLPServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 2575):
        self.host = host
        self.port = port
        self._sock = None
        self._running = False

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        self._running = True
        logger.info("HL7/MLLP interface listening on %s:%s (PLAINTEXT - no TLS)", self.host, self.port)
        while self._running:
            try:
                client, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()

    # ------------------------------------------------------------------ #

    def _handle(self, client: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        try:
            client.settimeout(10)
            buf = b""
            try:
                while b"\x1c" not in buf:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 5_000_000:   # 5MB hard stop
                        break
            except (socket.timeout, TimeoutError):
                # Client connected but didn't send a complete MLLP frame in time.
                # Normal noise during scanning/fuzzing, a browser hitting :2575,
                # or idle connections -- not an error, so log quietly (no stack trace).
                if not buf:
                    logger.info("[%s] connection idle/incomplete (no MLLP frame before timeout); closing", peer)
                    return
                logger.info("[%s] read timed out mid-message; processing %d partial bytes", peer, len(buf))

            if not buf:
                return

            raw = strip_mllp(buf).decode("utf-8", errors="replace")
            segments, by_name = parse_segments(raw)

            # --- VULN 3: no field-length bound -> "buffer overflow" crash ---
            for parts in segments:
                for field in parts.split("|"):
                    if len(field) > MAX_FIELD_LEN:
                        logger.error(
                            "!!! [%s] oversized field (%d bytes) - SIMULATED CRASH, dropping connection",
                            peer, len(field),
                        )
                        self._log(peer, by_name, raw, "NONE", "simulated buffer overflow: connection dropped")
                        try:
                            client.close()   # abrupt drop, no ACK -> client sees reset/timeout
                        except OSError:
                            pass
                        return

            ack = self._process(peer, raw, by_name)
            client.sendall(wrap_mllp(ack))
        except Exception as e:  # noqa: BLE001 - demo target stays up on any error
            logger.exception("handler error for %s: %s", peer, e)
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _process(self, peer: str, raw: str, by_name) -> str:
        patient = extract_patient(by_name)
        mrn = patient["mrn"]
        conn = db.get_conn()

        # --- VULN 2: SQL injection in the patient lookup ---
        # MRN is interpolated straight into SQL. Fuzzer payloads like
        # "' OR '1'='1" or a stray quote surface as reflected DB errors.
        lookup_sql = "SELECT id FROM patients WHERE mrn = '%s'" % mrn
        try:
            row = conn.execute(lookup_sql).fetchone()
        except sqlite3.Error as e:
            logger.warning("[%s] SQL error during MRN lookup: %s", peer, e)
            # Reflect the raw DB error back to the sender (classic error-based SQLi tell).
            self._log(peer, by_name, raw, "AE", f"SQL error: {e}")
            return build_ack(by_name, code="AE", text=f"Lookup failed: {e} [{lookup_sql}]")

        now = datetime.now(timezone.utc).isoformat()
        # --- VULN 4: patient name (and other fields) stored verbatim; the
        #     viewer renders them without escaping -> stored XSS. ---
        if row:
            conn.execute(
                "UPDATE patients SET family=?, given=?, dob=?, sex=?, ssn=?, "
                "last_order=?, last_result=?, msg_type=?, raw_hl7=?, received_at=? WHERE id=?",
                (patient["family"], patient["given"], patient["dob"], patient["sex"],
                 patient["ssn"], patient["order"], patient["result"], patient["msg_type"],
                 raw, now, row["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO patients (mrn, family, given, dob, sex, ssn, last_order, "
                "last_result, msg_type, raw_hl7, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (mrn, patient["family"], patient["given"], patient["dob"], patient["sex"],
                 patient["ssn"], patient["order"], patient["result"], patient["msg_type"], raw, now),
            )
        conn.commit()

        self._log(peer, by_name, raw, "AA", "accepted")
        logger.info("[%s] %s accepted for MRN=%r", peer, patient["msg_type"] or "message", mrn)
        return build_ack(by_name, code="AA", text="Message accepted")

    def _log(self, peer, by_name, raw, ack_code, note) -> None:
        try:
            patient = extract_patient(by_name)
            db.log_message(peer, patient.get("msg_type", ""), raw, ack_code, note,
                           datetime.now(timezone.utc).isoformat())
        except Exception:  # noqa: BLE001
            pass
