# Medaudit 2.0 — GitHub Copilot Instructions

Guide for GitHub Copilot to assist with medical device security auditing tool development.

## Project Overview
**Medaudit 2.0** analyzes HL7/FHIR medical device traffic for encryption & PII exposure. Core modules: PCAP analyzer, mock HL7 server, HTTP→HL7 proxy, FastAPI web UI, Presidio+regex PII detection.

## Quick Commands
```bash
# Analysis
python3 -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap

# Web UI (port 8080)
python3 -m medaudit web --host 0.0.0.0 --port 8080

# HTTP→HL7 proxy
python3 -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# Mock HL7 server
python3 -m hl7server start --host 0.0.0.0 --port 2575

# Config management
python3 -m medaudit config --show
```

## Key Files to Edit
- **PCAP Analysis**: `medaudit/analysis/traffic/traffic_analysis.py`
- **PII Detection**: `medaudit/analysis/pii/pii_check.py` (Presidio + regex)
- **HTTP→HL7 Proxy**: `medaudit/proxy/proxy_server.py`
- **Web API**: `medaudit/web/app.py` (FastAPI endpoints)
- **HL7 Server**: `medaudit/hl7server/hl7_mock_server.py` (MLLP handler)
- **CLI Router**: `medaudit/__main__.py` (subcommand entry)

## Core Patterns

### HL7 Detection
```python
# Check for MLLP-wrapped HL7 in payload
payload = pkt[Raw].load.decode('utf-8', errors='ignore')
if 'MSH|' in payload:
    # Extract HL7 message
```

### Encryption Heuristic
```python
# SSL ports: 443, 993, 995, 465, 587, 8443
# Entropy > 0.8 = likely encrypted
unique_bytes = len(set(payload))
entropy = unique_bytes / len(payload)
```

### MLLP Wrapping
```python
# HL7 transport: \x0b (start) + message + \x1c\r (end)
mllp_wrapped = b'\x0b' + hl7_msg.encode() + b'\x1c\r'
```

### Presidio PII Detection
```python
from medaudit.analysis.pii.pii_check import create_analyzer
analyzer = create_analyzer()  # Cached instance
results = analyzer.analyze(text=payload, language='en')
# Entities: PERSON, PHONE_NUMBER, EMAIL_ADDRESS, SSN, CREDIT_CARD, LOCATION
```

## Config System
- Precedence: CLI args → `config/medaudit.json` (preferred) → `medaudit.json` (backcompat) → `~/.medaudit.json` → `~/.config/medaudit.json` → defaults
- Keys: `proxy` (http_host, http_port, hl7_host, hl7_port), `analysis` (max_hl7_messages, max_pii_instances), `logging` (enabled, log_dir)

## Logging
- Format: JSON Lines (.jsonl)
- Path: `logs/YYYY-MM-DD/` (date-organized)
- Files: `proxy_activity.jsonl`, `http_requests.jsonl`, `hl7_responses.jsonl`, `proxy_errors.jsonl`

## Dependencies
- **Core**: scapy, rich
- **PII**: presidio-analyzer, presidio-anonymizer, spacy (`en_core_web_lg`)
- **Web**: fastapi, uvicorn, jinja2, python-multipart, aiofiles
- **Test**: pytest

## When Suggesting Code
1. Use `errors='ignore'` for all UTF-8 payload decoding (binary data safety)
2. Validate `MSH|` before parsing HL7
3. Cache Presidio analyzer instance (avoid Spacy reloads)
4. Keep output limits: 10 HL7 msgs, 20 PII instances
5. Use MLLP framing for HL7 transport
6. Maintain config cascading (no hardcoding values)

## Testing
- **PII**: `pytest tests/test_pii_check.py -v`
- **PCAP**: `python3 tests/analyze_pcap_pii.py`
- **HL7 Server**: `python3 -m pytest tests/test_hl7_server_client.py -v`
- **All**: `pytest -q`

## Medical Device Security Focus
- HL7 v2.x protocol analysis
- Unencrypted PII exposure detection
- Proxy testing with Burp Suite/ZAP
- Mock HL7 server for safe testing
