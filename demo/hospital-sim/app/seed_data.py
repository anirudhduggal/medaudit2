"""
Synthetic patient seed data for the demo hospital worklist.

100% fabricated. Names, MRNs, DOBs, SSNs are fake and do not correspond to real
individuals. Seeded on startup so the viewer looks like a live hospital worklist
before any pentest traffic arrives.
"""

from datetime import datetime, timezone

from . import db

# (mrn, family, given, dob, sex, ssn, order, result, msg_type)
SEED_PATIENTS = [
    ("100482", "Vega", "Maria", "19710302", "F", "412-55-8830", "CBC with Differential", "WBC: 7.2 | HGB: 13.1", "ORU^R01"),
    ("100483", "Okafor", "James", "19881119", "M", "301-22-9147", "CT Head without contrast", "", "ORM^O01"),
    ("100484", "Sorensen", "Lena", "19540718", "F", "556-73-1290", "Basic Metabolic Panel", "Na: 139 | K: 4.1 | Cr: 0.9", "ORU^R01"),
    ("100485", "Delacroix", "Andre", "19930205", "M", "233-90-6642", "Chest X-Ray PA/LAT", "", "ADT^A01"),
    ("100486", "Haddad", "Nour", "20010913", "F", "674-31-5508", "Lipid Panel", "LDL: 128 | HDL: 51", "ORU^R01"),
    ("100487", "Fitzgerald", "Sean", "19670428", "M", "128-44-7723", "Troponin I", "Troponin: 0.02 (normal)", "ORU^R01"),
]


def seed_if_empty() -> None:
    conn = db.get_conn()
    count = conn.execute("SELECT COUNT(*) AS c FROM patients").fetchone()["c"]
    if count:
        return
    now = datetime.now(timezone.utc).isoformat()
    for (mrn, family, given, dob, sex, ssn, order, result, mtype) in SEED_PATIENTS:
        raw = (
            f"MSH|^~\\&|EPIC|STELSEWHERE|LAB|STELSEWHERE|20240101120000||{mtype}|{mrn}0001|P|2.5\r"
            f"PID|1||{mrn}||{family}^{given}||{dob}|{sex}|||||||||||{ssn}\r"
        )
        conn.execute(
            "INSERT INTO patients (mrn, family, given, dob, sex, ssn, last_order, "
            "last_result, msg_type, raw_hl7, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (mrn, family, given, dob, sex, ssn, order, result, mtype, raw, now),
        )
    conn.commit()
