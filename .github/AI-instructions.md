# Medaudit 2.0 — Unified AI Instructions

Generalized guide for any AI agent (Copilot, Claude, Cursor, etc.) to work productively in this medical device security auditing tool.

## Project Summary
**Medaudit 2.0** analyzes HL7/FHIR medical device traffic for encryption status and PII exposure. Includes: PCAP analyzer, mock HL7 server, HTTP→HL7 proxy, FastAPI web UI, and PII detection (Presidio + regex hybrid).

## Project Folder Structure
```
medaudit2/
├── medaudit/                          # Main Python package
│   ├── __main__.py                    # CLI entry: python -m medaudit <cmd>
│   ├── config.py                      # Config loader (medaudit.json precedence)
│   ├── logging.py                     # Proxy activity logging (JSON Lines)
│   │
│   ├── analysis/                      # Traffic & PII analysis module
│   │   ├── __init__.py                # Unified export of all analysis functions
│   │   ├── traffic/
│   │   │   ├── traffic_analysis.py    # PCAP parsing, encryption detection, HL7 extraction
│   │   └── pii/
│   │       └── pii_check.py           # Presidio + regex PII detection
│   │
│   ├── proxy/                         # HTTP→HL7 converter
│   │   └── proxy_server.py            # HTTP server for Burp Suite/ZAP integration
│   │
│   ├── hl7server/                     # Mock HL7 2.x server
│   │   ├── __main__.py                # CLI entry: python -m hl7server
│   │   ├── hl7_mock_server.py         # Core MLLP server + ACK generation
│   │   ├── hl7_client.py              # Client library & message generators
│   │   ├── message_logger.py          # JSON Lines logging (separate files per type)
│   │   ├── server_config.py           # Server configuration management
│   │   ├── cli.py                     # Command-line interface
│   │   └── README.md                  # HL7 server docs
│   │
│   ├── web/                           # FastAPI web UI
│   │   ├── app.py                     # FastAPI app + /api/analyze endpoint
│   │   ├── analyzer.py                # Web analyzer (parse HL7, detect PII for UI)
│   │   ├── static/                    # CSS/JS assets
│   │   └── templates/
│   │       └── index.html             # Web UI form
│   │
│   └── testFiles/                     # Test PCAPs
│       ├── hl7_v2_unencrypted_synthetic.pcap
│       └── hl7_v2_unencrypted_synthetic_no_pii.pcap
│
├── tests/                             # Test suite
│   ├── test_pii_check.py              # PII detection unit tests
│   ├── test_comprehensive.py          # Core component tests
│   ├── test_pii_on_pcap.py            # PCAP PII extraction tests
│   ├── test_hl7_server_client.py      # HL7 server/client integration
│   ├── test_comprehensive_hl7.py      # Full HL7 workflow tests
│   ├── analyze_pcap_pii.py            # Standalone PCAP analysis script
│   ├── results/                       # Test execution reports & analysis results
│   ├── logs/                          # Proxy/test logs (date-organized, .gitignored)
│   └── fixtures/                      # Test data
│
├── .github/
│   └── AI-instructions.md             # This file (generalized AI guide)
│
├── pcap-generator.py                  # Synthetic PCAP generator (no scapy, raw struct)
├── pcap-samples/                      # Sample PCAP files (HL7, ADT, ORM, ORU types)
├── requirements.txt                   # Python dependencies
├── medaudit.json                      # Config file (optional, version-controlled)
├── README.md                          # Project overview & setup
└── venv/ or .venv/                    # Python virtual environment
```

## Quick Start (from root)
```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m spacy download en_core_web_lg

# Run commands
python3 -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
python3 -m medaudit web --host 0.0.0.0 --port 8080        # Then visit http://localhost:8080
python3 -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575
python3 -m hl7server start                                  # Mock HL7 server on port 2575
python3 -m medaudit config --show
```

## Key Entry Points & Commands

### 1. **PCAP Analysis**
```bash
python3 -m medaudit analyze <pcap_file>
```
Detects encryption, extracts HL7, finds PII. Output: console report + JSON-ready.

### 2. **Web UI (FastAPI)**
```bash
python3 -m medaudit web --host 0.0.0.0 --port 8080
# OR (dev with auto-reload):
uvicorn medaudit.web.app:app --reload --host 0.0.0.0 --port 8080
```
POST PCAP to `/api/analyze`, browse UI at `http://localhost:8080`.

### 3. **HTTP→HL7 Proxy**
```bash
python3 -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575
```
Converts HTTP POST requests to HL7, useful for Burp Suite/ZAP testing.

### 4. **Mock HL7 Server**
```bash
python3 -m hl7server start --host 0.0.0.0 --port 2575
python3 -m hl7server start --use-tls --cert-file cert.pem --key-file key.pem  # With TLS
```
Accepts MLLP-wrapped HL7, generates ACK responses, logs to JSON.

### 5. **Configuration**
```bash
python3 -m medaudit config --create  # Generate medaudit.json
python3 -m medaudit config --show    # Display loaded config
```

### 6. **Run Tests**
```bash
pytest tests/test_pii_check.py           # PII detection only
python3 tests/analyze_pcap_pii.py        # Full PCAP analysis
python3 -m pytest -q                     # All tests
```

## Architecture & Data Flow

### Analysis Pipeline
```
PCAP file
  ↓ (scapy rdpcap)
Ethernet frames → TCP/UDP packets
  ↓ (Raw payload extraction)
Payload bytes
  ↓ (UTF-8 decode, errors='ignore')
Text / binary check
  ↓ (SSL port + entropy heuristic)
Encryption determination
  ↓ (search for "MSH|" + MLLP framing)
HL7 v2.x message extraction
  ↓ (Presidio analyzer + regex patterns)
PII entity detection
  ↓ (structured JSON output)
Analysis report
```

### Proxy Pipeline
```
HTTP POST request (Burp Suite/ZAP)
  ↓ (parse body)
HL7 or raw message content
  ↓ (wrap in MLLP framing: \x0b...\x1c\r)
MLLP-wrapped HL7
  ↓ (TCP send to HL7 server)
Mock HL7 server (or real device)
  ↓ (ACK response)
Parse response
  ↓ (convert back to HTTP)
HTTP response to client
```

## Files to Check First (Fast Wins)

| File | Purpose |
|------|---------|
| `medaudit/__main__.py` | CLI entry point & subcommand routing |
| `medaudit/analysis/traffic/traffic_analysis.py` | PCAP parsing, encryption detection, HL7 extraction |
| `medaudit/analysis/pii/pii_check.py` | Presidio engine setup, Luhn validation, regex patterns |
| `medaudit/proxy/proxy_server.py` | HTTP→HL7 conversion, MLLP wrapping |
| `medaudit/web/app.py` | FastAPI routes + file upload handler |
| `medaudit/web/analyzer.py` | HL7 parsing for UI display, Presidio integration |
| `medaudit/hl7server/hl7_mock_server.py` | TCP server, MLLP frame handling, ACK generation |
| `medaudit/config.py` | Config file loading & precedence |
| `medaudit/logging.py` | JSON Lines logging (date-organized folders) |
| `requirements.txt` | Dependencies (scapy, fastapi, presidio, spacy, uvicorn) |

## Project-Specific Conventions & Patterns

### Encryption Detection (Heuristic)
- **SSL Ports**: 443, 993, 995, 465, 587, 8443 → encrypted
- **Payload Entropy**: If entropy > 0.8, likely encrypted
- Used in both CLI analysis and web UI; no deep inspection.

### HL7 Identification
- **Marker**: `MSH|` at payload start (after MLLP framing removal)
- **MLLP Frames**: `\x0b` (start) + message + `\x1c\r` (end)
- **Parsing**: Pipe-delimited fields; caret (`^`) for subcomponents (e.g., `LASTNAME^FIRSTNAME`)

### PII Detection (Hybrid)
- **Presidio Analyzer** (NLP): `AnalyzerEngine(nlp_engine_provider=NlpEngineProvider(model='en_core_web_lg'))`
  - Entities: PERSON, PHONE_NUMBER, EMAIL_ADDRESS, SSN, CREDIT_CARD, LOCATION
- **Regex Fallbacks**: Credit cards (Luhn validated), phone numbers, addresses
- **HL7 Field Context**: Extract PII from MSH, PID, PV1 segments
- **Caching**: Analyzer instance cached globally to avoid repeated Spacy loads

### Output Limits (to prevent noise)
- Max 10 HL7 messages displayed
- Max 20 PII instances flagged
- Config keys: `analysis.max_hl7_messages`, `analysis.max_pii_instances`

### Configuration Precedence
1. Command-line arguments (highest priority)
2. `medaudit.json` (current dir)
3. `~/.medaudit.json` (user home)
4. `~/.config/medaudit.json` (XDG)
5. Hardcoded defaults (lowest priority)

### Logging System
- **Format**: JSON Lines (.jsonl)
- **Organization**: `logs/YYYY-MM-DD/` (date-based folders)
- **Files**: Separate for `proxy_activity.jsonl`, `http_requests.jsonl`, `hl7_responses.jsonl`, `proxy_errors.jsonl`
- **Disabled by default** in analysis; enabled for proxy server

### Modular Imports
```python
# Unified imports
from medaudit.analysis import analyze_pcap, detect_pii
from medaudit.proxy import start_proxy
from medaudit.web import start_web_server

# Direct imports
from medaudit.analysis.traffic import detect_encryption, extract_hl7
from medaudit.analysis.pii import detect_pii_in_text
```

## Common Patterns & Code Examples

### Extract HL7 from PCAP Payload
```python
from scapy.all import rdpcap, Raw, TCP
packets = rdpcap('file.pcap')
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        if 'MSH|' in payload:
            # Found HL7 message
            print(payload)
```

### Detect Encryption via Entropy
```python
def is_encrypted(payload: bytes) -> bool:
    unique_bytes = len(set(payload))
    entropy = unique_bytes / len(payload)
    return entropy > 0.8
```

### MLLP Wrapping Example
```python
hl7_msg = "MSH|^~\\&|..."
mllp_wrapped = b'\x0b' + hl7_msg.encode() + b'\x1c\r'
socket.sendall(mllp_wrapped)
```

### Presidio PII Detection
```python
from medaudit.analysis.pii.pii_check import create_analyzer
analyzer = create_analyzer()
results = analyzer.analyze(text="John Doe, SSN 123-45-6789", language='en')
for result in results:
    print(f"{result.entity_type}: {text[result.start:result.end]}")
```

## Developer Workflows

### Adding a New Analysis Module
1. Create `medaudit/analysis/<module_name>/` directory
2. Add `__init__.py` + implementation files
3. Export functions in `medaudit/analysis/__init__.py`
4. Follow pattern in `traffic/` or `pii/`

### Extending PII Detection
1. Edit `medaudit/analysis/pii/pii_check.py`
2. Add custom Presidio recognizers or regex patterns
3. Test with `tests/test_pii_check.py` and `tests/test_pii_on_pcap.py`
4. Update Spacy model setup if needed

### Testing Changes
```bash
# PII detection only
pytest tests/test_pii_check.py -v

# PCAP analysis
python3 tests/analyze_pcap_pii.py

# HL7 server integration
python3 -m pytest tests/test_hl7_server_client.py -v

# All tests
pytest -q
```

## Quick Gotchas & Best Practices

### ⚠️ Don't
- Assume UTF-8 decoding will always work → use `errors='ignore'`
- Validate HL7 without checking `MSH|` prefix first
- Modify global Presidio analyzer instance during concurrent requests
- Skip caching the Spacy NLP engine (huge startup cost)

### ✅ Do
- Handle binary payloads gracefully in PCAP analysis
- Test PII detection with `tests/test_pii_on_pcap.py` when modifying regex
- Use MLLP framing (`\x0b...\x1c\r`) for HL7 transport
- Keep config cascading (CLI args → file → defaults)
- Log proxy activity to JSON for forensic analysis

## Dependencies
- **Core**: `scapy` (PCAP parsing), `rich` (console output)
- **PII**: `presidio-analyzer`, `presidio-anonymizer`, `spacy` (with `en_core_web_lg` model)
- **Web**: `fastapi`, `uvicorn[standard]`, `jinja2`, `python-multipart`, `aiofiles`
- **Test**: `pytest`, `pyshark` (optional)

Install all:
```bash
pip install -r requirements.txt
python3 -m spacy download en_core_web_lg
```

## Medical Device Security Context
- Focus: HL7 v2.x encryption analysis, unencrypted PII detection, proxy testing with Burp/ZAP
- Tools integrate: Mock HL7 server enables testing without real devices; proxy allows HTTP tool integration
- Output: Security audit reports; JSON logs for SIEM integration; web UI for quick analysis
