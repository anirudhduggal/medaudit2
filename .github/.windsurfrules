# .windsurfrules — Medaudit 2.0 Development Guidelines

## Project Identity
Medical device security analyzer for HL7/FHIR traffic with PCAP analysis, real-time web UI, HTTP→HL7 proxy, mock HL7 server, and AI-assisted PII detection.

## Quick Navigation
- **Start**: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- **Analyze PCAP**: `python3 -m medaudit analyze <file.pcap>`
- **Web UI**: `python3 -m medaudit web --port 8080` (then `http://localhost:8080`)
- **Proxy**: `python3 -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575`
- **HL7 Server**: `python3 -m medaudit.hl7server start --port 2575`

## Key Code Locations
| Task | File |
|------|------|
| PCAP analysis logic | `medaudit/analysis/traffic/traffic_analysis.py` |
| PII detection | `medaudit/analysis/pii/pii_check.py` |
| HTTP→HL7 proxy | `medaudit/proxy/proxy_server.py` |
| Web API | `medaudit/web/app.py` |
| Mock HL7 server | `medaudit/hl7server/hl7_mock_server.py` |
| CLI dispatcher | `medaudit/__main__.py` |

## Design Principles
- **Modular**: Each subsystem (analysis, proxy, server, web) is independent
- **Heuristic-first**: Use lightweight detection (entropy, port heuristics) before heavy ML
- **Security-focused**: Prioritize PII exposure detection in unencrypted traffic
- **Developer-friendly**: Config cascading, structured logging, clear error messages

## Core Workflows

### PCAP Analysis Pipeline
```
Load PCAP → Extract packets → Decode payloads (UTF-8, errors='ignore')
  → Detect encryption (SSL ports + entropy heuristic)
  → Find HL7 (search for "MSH|" marker)
  → Remove MLLP framing (\x0b...\x1c\r)
  → Parse HL7 segments (pipe-delimited, caret-separated subcomponents)
  → Scan for PII (Presidio NLP + regex patterns)
  → Generate JSON report
```

### Proxy Workflow
```
HTTP POST (Burp/ZAP) → Parse body → Wrap in MLLP (\x0b...\x1c\r)
  → Send to HL7 server → Wait for ACK → Parse response
  → Extract HL7 → Convert back to HTTP JSON → Return to client
```

## Coding Standards

### Error Handling
```python
# Always use errors='ignore' for binary payloads
payload = pkt[Raw].load.decode('utf-8', errors='ignore')

# Validate before parsing
if 'MSH|' in payload:
    # Safe to parse as HL7
```

### HL7 Message Handling
```python
# MLLP wrapping (required for HL7 devices)
message = "MSH|^~\\&|APP|FAC|..."
mllp_wrapped = b'\x0b' + message.encode() + b'\x1c\r'

# MLLP unwrapping
if text.startswith('\x0b'):
    text = text[1:]
if '\x1c' in text:
    text = text.split('\x1c')[0]
```

### PII Detection
```python
# Initialize once, reuse globally
from medaudit.analysis.pii.pii_check import create_analyzer
analyzer = create_analyzer()  # Cached instance

# Analyze text
results = analyzer.analyze(text=payload, language='en')
for entity in results:
    print(f"{entity.entity_type}: {payload[entity.start:entity.end]}")
```

### Configuration Loading
```python
# Use config class, never hardcode
from config import config
proxy_config = config.get_proxy_config()
hl7_host = proxy_config['hl7_host']  # Respects precedence
```

## Output Constraints
- Analysis displays max 10 HL7 messages (prevent UI overload)
- Report includes max 20 PII instances (manageable for review)
- Web UI supports file upload (PCAP, PCAPNG, CAP formats)
- Logs: JSON Lines format in date-organized folders (logs/YYYY-MM-DD/)

## Testing Requirements
- **PII changes**: `pytest tests/test_pii_check.py -v`
- **PCAP logic**: `python3 tests/analyze_pcap_pii.py`
- **HL7 server**: `pytest tests/test_hl7_server_client.py -v`
- **Full suite**: `pytest -q`

## File Structure
```
medaudit/
├── __main__.py
├── config.py
├── logging.py
├── analysis/
│   ├── traffic/traffic_analysis.py
│   └── pii/pii_check.py
├── proxy/proxy_server.py
├── hl7server/
│   ├── hl7_mock_server.py
│   ├── hl7_client.py
│   ├── server_config.py
│   └── message_logger.py
└── web/
    ├── app.py
    ├── analyzer.py
    └── templates/
```

## Dependencies
- Core: scapy, rich
- PII: presidio-analyzer, presidio-anonymizer, spacy
- Web: fastapi, uvicorn[standard], jinja2, python-multipart
- Ops: pytest

## Common Pitfalls
- ❌ Skipping `errors='ignore'` on binary payloads → crashes
- ❌ Parsing HL7 without MSH| check → false positives
- ❌ Recreating Spacy model per request → 10x+ slowdown
- ❌ Hardcoding config values → breaks portability
- ❌ Missing MLLP framing in proxy → HL7 device rejection

## Security Context
This tool audits medical devices for:
- **Encryption**: Determines if traffic is encrypted (heuristic-based)
- **PII Exposure**: Detects patient data in unencrypted HL7 (critical risk)
- **Protocol Compliance**: Validates HL7 v2.x + MLLP framing
- **Proxy Testing**: Enables Burp/ZAP integration for device fuzzing
