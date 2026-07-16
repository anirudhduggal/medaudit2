# St. Elsewhere Hospital — vulnerable HL7 demo target

A containerized, **deliberately insecure** hospital HL7 interface + clinical
worklist viewer, built to demonstrate medaudit2 against a realistic healthcare
system. Think DVWA / OWASP Juice Shop, but for HL7 v2.x / MLLP.

```
   medaudit2  ──HL7/MLLP──▶  St. Elsewhere interface (:2575)  ──▶  SQLite
  (pentester)                          │
                                       ▼
                            Clinical worklist viewer (:8081)  ◀── clinician's browser
```

## ⚠️ Safety

- **Intentionally vulnerable** — it exists to be attacked, in isolation, by you.
- **100% synthetic data** — all patients, MRNs, DOBs, SSNs are fabricated.
- Ports bind to **127.0.0.1 only** (see `docker-compose.yml`). Do **not** expose
  it to a network, and never point it at, or feed it, real PHI.
- For **authorized security testing and training only.**

## Planted weaknesses → what medaudit2 shows

| # | Weakness | Where | medaudit2 capability demonstrated |
|---|----------|-------|-----------------------------------|
| 1 | Plaintext transport (no TLS) | MLLP listener | PCAP capture + PII/Presidio + "unencrypted" finding |
| 2 | SQL injection in PID-3 MRN lookup | `mllp_server.py` | Fuzzer SQLi payloads → reflected DB errors (AE ACK) |
| 3 | No field-size bound → crash | `mllp_server.py` | Fuzzer `overflow` → connection drop / timeout finding |
| 4 | Stored XSS (PID-5 rendered unescaped) | `viewer.py` + templates | Send crafted HL7 → script runs in the clinician's browser |

## Run it

```bash
cd demo/hospital-sim
docker compose up --build
```

- HL7/MLLP feed: `localhost:2575`
- Clinical viewer: http://localhost:8081

To run without Docker (needs Python 3 + Flask):

```bash
cd demo/hospital-sim
pip install -r requirements.txt
python -m app.main          # from the hospital-sim directory
```

Then follow [`DEMO.md`](DEMO.md) for the full guided walkthrough, or paste the
payloads in [`attacks/sample-messages.md`](attacks/sample-messages.md).

## Reset

The worklist lives in `data/hospital.db`. Delete it (or rebuild the container)
to return to the clean seeded state:

```bash
docker compose down && docker compose up --build   # container
rm -f data/hospital.db                              # local run
```
