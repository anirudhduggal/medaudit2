# Demo walkthrough — pentesting St. Elsewhere Hospital with medaudit2

A ~10-minute narrative that shows every core medaudit2 capability against a
realistic (fake) hospital. All data is synthetic; run everything on localhost.

## Setup (two terminals)

**Terminal 1 — the target:**
```bash
cd demo/hospital-sim
docker compose up --build
```
Open http://localhost:8081 — you'll see St. Elsewhere's seeded worklist
(Vega, Okafor, Sorensen, …). This is the "hospital" you're authorized to test.

**Terminal 2 — the tool:**
```bash
python -m medaudit web --port 8080 --password "DemoPass123!"
```
Open http://localhost:8080, log in, create a project **"St. Elsewhere Engagement"**.

---

## Act 1 — Reconnaissance & baseline (prove the link)

1. In the **Client** tab, set target `localhost` : `2575`, TLS **off**.
2. Send the baseline ADT from `attacks/sample-messages.md` (#1).
3. You get an `AA` ACK; refresh the viewer — the new patient is on the worklist.
   *Narration: "We have an authenticated-free HL7 feed into a live clinical system."*

## Act 2 — Cleartext PHI (no encryption)

1. Point out the feed is plaintext MLLP (no TLS) — note the Client tab TLS is off
   and it still works.
2. Capture loopback traffic (Wireshark/tcpdump on `lo`/`lo0`, port 2575) while
   sending a message, then run **Traffic** analysis in medaudit2.
3. PII detection flags patient **names, DOBs, and SSNs in the clear**, with an
   **unencrypted** verdict. *Narration: "PHI is crossing the wire unprotected —
   a HIPAA-reportable exposure."*

## Act 3 — Automated fuzzing (find the flaws)

1. In the **Fuzzer** tab, load `attacks/fuzz-hospital.yaml` (or point the tab's
   target at `localhost:2575` and start). It's a localhost target, so the
   blast-radius guard lets it run with no confirmation.
2. Watch findings roll in:
   - **SQL injection** — `SQLi in MRN` rule produces `AE` ACKs reflecting raw
     SQLite errors → the tool flags interesting responses.
   - **Crash/instability** — `Overflow patient name` drops connections → timeout
     / connection-error findings (the fragile-device scenario).
3. *Narration: "Unauthenticated input reaches a SQL query and can crash the
   interface — this is how you take a device offline mid-shift."*

## Act 4 — Manual exploitation: stored XSS in the clinician's view (the money shot)

1. Back in the **Client** tab, send payload #2 from `attacks/sample-messages.md`
   (the `<script>` in the patient name).
2. `AA` ACK — the hospital happily accepted it.
3. Refresh http://localhost:8081 — the script **executes in the clinician's
   browser**. *Narration: "An HL7 message just ran code in the hospital's EHR
   viewer. Swap the alert for a keylogger or PHI-exfil and it's game over."*

## Act 5 — Let the AI co-pilot summarize

1. Open the **AI sidebar**, select your provider (e.g. **OpenRouter**), and ask
   *"Summarize the vulnerabilities found in this engagement and rank by risk."*
2. It pulls the project context (fuzzer findings, PCAP/PII results, client
   history) and produces a prioritized writeup with suggested next steps.

---

## Reset between runs

```bash
docker compose down && docker compose up --build     # fresh seeded worklist
```

## Talking points / mapping

| Act | medaudit2 feature | Finding on the target |
|-----|-------------------|-----------------------|
| 1 | Client / MLLP send | Unauthenticated HL7 ingestion |
| 2 | PCAP + PII detection | Cleartext PHI, no TLS |
| 3 | Fuzzer + blast-radius guard | SQLi + crash/instability |
| 4 | Client / crafted payload | Stored XSS in clinical viewer |
| 5 | AI pentest co-pilot | Auto-generated risk summary |
