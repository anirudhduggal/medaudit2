# Medaudit 2.0 — AI Agent Instructions

Medical device security analyzer for HL7/FHIR traffic. Detects encryption status, extracts HL7 v2.x messages, identifies PII exposure using Presidio NLP + regex patterns.

## Architecture Overview
```
medaudit/
├── __main__.py                    # CLI dispatcher (analyze|web|proxy|config)
├── analysis/
│   ├── traffic/traffic_analysis.py   # PCAP parsing, encryption heuristics, HL7 extraction
│   └── pii/pii_check.py              # Presidio analyzer + custom recognizers
├── proxy/proxy_server.py             # HTTP→HL7 converter for Burp/ZAP testing
├── hl7server/hl7_mock_server.py      # MLLP-compliant mock server with ACK responses
└── web/app.py                        # FastAPI: POST /api/analyze, GET /
```

## Essential Commands
```bash
python3 -m medaudit analyze <file.pcap>           # Analyze PCAP for encryption + PII
python3 -m medaudit web --port 8080               # Start web UI
python3 -m medaudit proxy --hl7-port 2575         # HTTP→HL7 proxy for security testing
python3 -m medaudit.hl7server start --port 2575   # Mock HL7 server (separate module)
```

## Critical Code Patterns

### MLLP Protocol (Required for HL7 Transport)
```python
MLLP_START, MLLP_END = b'\x0b', b'\x1c\x0d'
mllp_wrapped = MLLP_START + hl7_msg.encode() + MLLP_END
# Unwrap: strip \x0b prefix, split on \x1c
```

### Binary Payload Decoding (Always Use)
```python
payload = pkt[Raw].load.decode('utf-8', errors='ignore')  # NEVER omit errors='ignore'
if 'MSH|' in payload:  # Validate before parsing as HL7
```

### PII Detection (Cache Analyzer Instance)
```python
from medaudit.analysis.pii.pii_check import create_analyzer
analyzer = create_analyzer()  # Expensive—reuse this instance
results = analyzer.analyze(text=payload, language='en')
```

### Encryption Detection Heuristics
- SSL ports (443, 993, 995, 465, 587, 8443) → encrypted
- Payload entropy > 0.8 → likely encrypted (high unique byte ratio)

## Error Handling Pattern (Required)
All modules must log errors and continue gracefully—never crash on bad input:
```python
import logging
logger = logging.getLogger(__name__)

try:
    result = risky_operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    # Return safe default or skip, don't re-raise unless critical
    return None  # or continue processing other items
```
- **PCAP parsing**: Skip malformed packets, log and continue
- **HL7 parsing**: Return partial results if segments are malformed
- **PII detection**: Catch Presidio/Spacy errors, return empty results
- **Network ops**: Use timeouts, log connection failures, return graceful error responses

## Configuration Precedence
CLI args → `config/medaudit.json` → `./medaudit.json` → `~/.medaudit.json` → defaults

## Output Limits (Enforced)
- Max 10 HL7 messages displayed per analysis
- Max 20 PII instances reported
- Logs: JSON Lines in `logs/YYYY-MM-DD/*.jsonl`

## Testing & Verification

### Run Full Integration Test (Verifies All Functionality)
```bash
python3 tests/test_comprehensive.py      # Tests: imports, config, logging, traffic, PCAP, proxy
python3 tests/test_comprehensive_hl7.py  # Tests: HL7 server startup, client connection, message flow
```

### Component-Specific Tests
```bash
pytest tests/test_pii_check.py -v        # PII detection accuracy
pytest tests/test_hl7_server_client.py   # HL7 server/client integration
python3 tests/analyze_pcap_pii.py        # Manual PCAP→PII pipeline test
```

### Quick Smoke Test (All Systems)
```bash
pytest -q                                # Run all pytest-compatible tests
```

### End-to-End Workflow Test
```bash
# Terminal 1: Start HL7 server
python3 -m medaudit.hl7server start --port 2575

# Terminal 2: Start proxy
python3 -m medaudit proxy --port 8080 --hl7-port 2575

# Terminal 3: Send test message
curl -X POST http://localhost:8080/ -d 'MSH|^~\&|TEST|LAB|EHR|HOSP|202601311200||ADT^A01|MSG001|P|2.5'
```

## Setup (Post-clone)
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg  # Required for Presidio NLP
```

## Key Constraints
1. Never hardcode config values—use `config.get_proxy_config()` etc.
2. Always validate `MSH|` marker before treating data as HL7
3. MLLP framing is mandatory for HL7 device communication
4. Presidio analyzer uses Spacy `en_core_web_lg`—slow to initialize, cache it
5. Log all errors with context, never let exceptions crash the program
