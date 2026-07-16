"""
Minimal HL7 v2.x parsing helpers for the demo hospital target.

Intentionally small and lenient -- just enough to pull patient/order/result
fields out of ADT/ORM/ORU messages and to build ACKs. This is a DEMO target,
not a production interface engine.
"""

from typing import Dict, List, Tuple

# MLLP framing bytes
MLLP_START = b"\x0b"
MLLP_END = b"\x1c\x0d"


def strip_mllp(data: bytes) -> bytes:
    """Remove MLLP framing if present."""
    if data.startswith(MLLP_START):
        data = data[1:]
    if data.endswith(MLLP_END):
        data = data[:-2]
    elif data.endswith(b"\x1c"):
        data = data[:-1]
    return data


def wrap_mllp(message: str) -> bytes:
    """Wrap a message in MLLP framing for the wire."""
    return MLLP_START + message.encode("utf-8", errors="replace") + MLLP_END


def _field(parts: List[str], idx: int) -> str:
    return parts[idx] if 0 <= idx < len(parts) else ""


def _component(value: str, idx: int, sep: str = "^") -> str:
    comps = value.split(sep)
    return comps[idx] if 0 <= idx < len(comps) else ""


def parse_segments(raw: str) -> Tuple[List[str], Dict[str, List[List[str]]]]:
    """
    Split a decoded HL7 message into segments and a {segment_name: [fields,...]}
    map. Segments may repeat (e.g. multiple OBX), hence a list per name.
    """
    normalized = raw.replace("\r\n", "\r").replace("\n", "\r")
    segments = [s for s in normalized.split("\r") if s.strip()]
    by_name: Dict[str, List[List[str]]] = {}
    for seg in segments:
        parts = seg.split("|")
        by_name.setdefault(parts[0], []).append(parts)
    return segments, by_name


def extract_patient(by_name: Dict[str, List[List[str]]]) -> Dict[str, str]:
    """
    Pull the demo's fields of interest out of a parsed message.

    Note on HL7 indexing: for the PID segment, parts[n] == field PID-n
    (PID-1 is the set id). MSH is special (MSH-1 is the field separator).
    """
    pid = by_name.get("PID", [[]])[0]
    name_field = _field(pid, 5)          # PID-5: family^given^middle
    result = {
        "mrn": _field(pid, 3),           # PID-3: patient identifier (MRN)
        "family": _component(name_field, 0),
        "given": _component(name_field, 1),
        "dob": _field(pid, 7),           # PID-7: date of birth
        "sex": _field(pid, 8),           # PID-8: administrative sex
        "ssn": _field(pid, 19),          # PID-19: SSN (cleartext PHI!)
        "order": "",
        "result": "",
        "msg_type": "",
    }

    # Order (ORM): OBR-4 universal service id, or ORC-based
    obr = by_name.get("OBR")
    if obr:
        result["order"] = _component(_field(obr[0], 4), 1) or _field(obr[0], 4)

    # Result (ORU): first OBX observation value
    obx = by_name.get("OBX")
    if obx:
        vals = [f"{_component(_field(o, 3), 1) or _field(o, 3)}: {_field(o, 5)}" for o in obx]
        result["result"] = " | ".join(v for v in vals if v.strip(": "))

    # Message type from MSH-9 (parts[8] for MSH)
    msh = by_name.get("MSH", [[]])[0]
    result["msg_type"] = _field(msh, 8)
    return result


def build_ack(by_name: Dict[str, List[List[str]]], code: str = "AA", text: str = "") -> str:
    """
    Build an HL7 ACK. code AA = accept, AE = application error (used to reflect
    the DB error in the SQL-injection path), AR = reject.
    """
    msh = by_name.get("MSH", [[]])[0]
    control_id = _field(msh, 9) or "UNKNOWN"      # MSH-10
    sending_app = _field(msh, 2) or "SENDER"
    ts = "20240101000000"
    ack = (
        f"MSH|^~\\&|HOSPITAL|STELSEWHERE|{sending_app}|MEDAUDIT|{ts}||ACK|{control_id}|P|2.5\r"
        f"MSA|{code}|{control_id}|{text}\r"
    )
    return ack
