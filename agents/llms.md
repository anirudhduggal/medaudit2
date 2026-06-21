# llms.txt — Medaudit 2.0 AI Instructions

## System Context
Medaudit 2.0 is a Python-based medical device security auditing tool for analyzing HL7/FHIR traffic, detecting encryption status, extracting HL7 v2.x messages, and identifying PII in unencrypted communications using Presidio NLP + regex hybrid detection.

## Quick Start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m spacy download en_core_web_lg
python3 -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
python3 -m medaudit web --host 0.0.0.0 --port 8080
```

## Architecture Overview
```
Input (PCAP) → Scapy parsing → Encryption detection → HL7 extraction → PII scanning → JSON report
```

### Key Modules
- **analysis/traffic/** → PCAP parsing, encryption heuristic, HL7 detection
- **analysis/pii/** → Presidio analyzer + regex patterns for entities
- **proxy/** → HTTP to MLLP-wrapped HL7 converter
- **hl7server/** → Mock HL7 2.x server with ACK generation
- **web/** → FastAPI UI with PCAP upload and real-time analysis
- **config.py** → Multi-level config loading (CLI → files → defaults)

## Critical Patterns

### HL7 v2.x Protocol
- Format: `MSH|^~\\&|SendingApp|SendingFac|...`
- Transport: MLLP (Minimal Lower Layer Protocol)
- MLLP frame: `\x0b` (start VT) + message + `\x1c\r` (end FS+CR)
- Segments separated by `\r` or `\n`
- Fields pipe-delimited; subcomponents caret-delimited (`^`)

### Encryption Detection (Heuristic)
- SSL/TLS ports: 443, 993, 995, 465, 587, 8443
- Payload entropy analysis: high entropy (>0.8) suggests encryption
- No deep cryptographic inspection

### PII Detection (Hybrid)
- **NLP**: Presidio Analyzer + Spacy en_core_web_lg (PERSON, ORG, LOCATION, PHONE_NUMBER, EMAIL, SSN, CREDIT_CARD)
- **Regex**: Credit cards (Luhn validated), SSN, phone, addresses, financial keywords
- **HL7 fields**: Extract from MSH, PID (patient ID, name, DOB, SSN), PV1 (visit info)
- **Caching**: Global analyzer instance to avoid repeated model loads

### Configuration Precedence
1. CLI arguments (highest)
2. ./config/medaudit.json (preferred)
3. ./medaudit.json (backwards-compatible)
4. ~/.medaudit.json
5. ~/.config/medaudit.json
5. Hardcoded defaults (lowest)

## File Locations
- Analysis modules: `medaudit/analysis/` (traffic, pii subpackages)
- Web UI: `medaudit/web/app.py` (FastAPI), analyzer.py (HL7 parsing for web)
- Proxy: `medaudit/proxy/proxy_server.py` (HTTP server converting to MLLP)
- HL7 Server: `medaudit/hl7server/hl7_mock_server.py` (TCP MLLP listener)
- Tests: `tests/test_pii_check.py`, `tests/analyze_pcap_pii.py`, `tests/test_hl7_server_client.py`

## Common Tasks

### Add New PII Pattern
Edit `medaudit/analysis/pii/pii_check.py`:
1. Add regex pattern or custom Presidio recognizer
2. Test with `pytest tests/test_pii_check.py -v`
3. Verify on real PCAP: `python3 tests/analyze_pcap_pii.py`

### Fix PCAP Parsing Issue
Edit `medaudit/analysis/traffic/traffic_analysis.py`:
1. Import scapy layers as needed (TCP, UDP, Raw, IP)
2. Decode payload with `errors='ignore'` (handle binary)
3. Search for `MSH|` marker
4. Extract MLLP framing (`\x0b...\x1c\r`)

### Extend Proxy Features
Edit `medaudit/proxy/proxy_server.py`:
1. Modify HTTP request handler to add transformations
2. Ensure MLLP wrapping maintained
3. Test with mock HL7 server on port 2575

## Dependencies & Versions
- Python 3.8+
- scapy (PCAP), fastapi (web), uvicorn (server), presidio-analyzer (PII), spacy (NLP)
- See requirements.txt for complete list

## Output Constraints
- Max 10 HL7 messages per analysis (prevent noise)
- Max 20 PII instances reported
- JSON Lines logging (structured, SIEM-friendly)

## Medical Device Context
- HL7 v2.x is healthcare standard for patient/order data
- MLLP is transport layer (no encryption built-in)
- PII in unencrypted HL7 is critical security issue
- Mock server enables safe testing without real devices
- Proxy + Burp Suite allows fuzzing and interception

## Best Practices
- Always use `errors='ignore'` for binary payload decoding
- Validate `MSH|` before treating as HL7
- Cache Presidio analyzer (huge startup cost)
- Maintain MLLP framing in proxy (required for HL7 devices)
- Log all proxy activity to JSON (forensics)
- Test PII changes with synthetic PCAP before production
