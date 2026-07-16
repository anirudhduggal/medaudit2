"""
Clinical worklist viewer for the demo hospital.

⚠️  INTENTIONALLY VULNERABLE. Patient fields populated from the HL7 feed are
    rendered with Jinja's |safe filter (no HTML escaping), so a crafted PID-5
    name segment becomes stored XSS that executes in the clinician's browser.
    This mirrors real-world "we used |safe to keep formatting" mistakes.
"""

from flask import Flask, render_template, abort

from . import db

app = Flask(__name__)


@app.route("/")
def worklist():
    conn = db.get_conn()
    patients = conn.execute(
        "SELECT * FROM patients ORDER BY received_at DESC, id DESC"
    ).fetchall()
    return render_template("worklist.html", patients=patients)


@app.route("/patient/<int:pid>")
def patient_detail(pid: int):
    conn = db.get_conn()
    row = conn.execute("SELECT * FROM patients WHERE id = ?", (pid,)).fetchone()
    if not row:
        abort(404)
    return render_template("patient.html", p=row)


@app.route("/feed")
def feed():
    conn = db.get_conn()
    messages = conn.execute(
        "SELECT * FROM messages ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return render_template("feed.html", messages=messages)
