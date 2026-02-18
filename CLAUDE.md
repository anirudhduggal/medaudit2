# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Medaudit 2.0 is a medical device security analyzer for HL7 v2.x and FHIR traffic. It provides PCAP traffic analysis, PII detection (Presidio NLP + regex), HTTP-to-HL7 proxying for Burp/ZAP integration, mock HL7 servers, HL7 fuzzing, and a full-stack FastAPI web UI with authentication.

## Common Commands

```bash
# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg  # Required one-time download (~500MB)

# CLI Analysis
python -m medaudit analyze <file.pcap>

# Web UI (default admin: admin/admin123, change immediately)
python -m medaudit web --host 0.0.0.0 --port 8080
python -m medaudit web --generate-password  # Random secure admin password

# HTTP-to-HL7 Proxy (for Burp/ZAP)
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# HL7 Mock Server (standalone, separate entry point)
python -m medaudit.hl7server start --port 2575
python -m medaudit.hl7server config --show

# HL7 Fuzzer (standalone, separate entry point)
python -m medaudit.fuzzer run -c config.yaml -o results.json
python -m medaudit.fuzzer test --host localhost --port 2575
python -m medaudit.fuzzer template --format yaml > fuzzer.yaml
python -m medaudit.fuzzer server --mode no_ack --port 2575  # Malicious server (17 attack modes)
python -m medaudit.fuzzer attacks  # List all attack modes

# User management (requires web server running)
python -m medaudit user --create --username john --password pass123

# Configuration
python -m medaudit config --show
python -m medaudit config --create

# Run all tests
pytest tests/ -v

# Run specific test files
pytest tests/test_pii_check.py -v
pytest tests/test_hl7_server_client.py -v
pytest tests/test_ai_api.py -v
pytest tests/test_logging_system.py -v

# Manual pipeline test (not pytest-based)
python tests/analyze_pcap_pii.py
```

## Architecture

The CLI dispatcher (`medaudit/__main__.py`) routes to five subcommands: `analyze`, `web`, `proxy`, `config`, `user`. The HL7 server and fuzzer have their own `__main__.py` entry points (`python -m medaudit.hl7server`, `python -m medaudit.fuzzer`).

```
medaudit/
├── __main__.py              # CLI dispatcher (analyze|web|proxy|config|user)
├── utils/paths.py           # Centralized path management for all data/config/logs
├── config/                  # Config module + JSON files (medaudit.json, hl7server.json)
│   └── __init__.py          # Config class with global `config` singleton
├── analysis/
│   ├── traffic/traffic_analysis.py  # Scapy PCAP parsing, encryption detection, HL7 extraction
│   └── pii/pii_check.py            # Presidio NLP + regex PII detection
├── proxy/proxy_server.py    # HTTP→MLLP HL7 converter for Burp/ZAP integration
├── hl7server/               # Standalone MLLP server + client library
│   ├── hl7_mock_server.py   # Multi-threaded MLLP server with ACK responses
│   ├── hl7_client.py        # Client for sending ADT/ORM/ORU/MDM messages
│   └── message_logger.py    # JSON Lines message logging
├── fuzzer/                  # Standalone HL7 fuzzing engine
│   ├── engine.py            # Fuzzing execution + message generation
│   ├── strategies.py        # Mutation strategies (field, segment, delimiter, overflow, injection)
│   ├── malicious_hl7_server.py  # Attack server with 17 modes (no_ack, flood, overflow, etc.)
│   └── protocol.py          # HL7/MLLP protocol handling
├── web/                     # FastAPI web platform
│   ├── app.py               # Main app, routes, SecurityHeadersMiddleware, startup
│   ├── auth.py              # Authentication, sessions, rate limiting, registration
│   ├── database.py          # SQLAlchemy models + DatabaseManager singleton
│   ├── projects.py          # Project CRUD API (/api/projects)
│   ├── client_api.py        # HL7 Client API + malformed payload library
│   ├── fuzzer_api.py        # Fuzzer Web API
│   ├── traffic_api.py       # PCAP upload + analysis + network visualization
│   ├── server_api.py        # Managed HL7 server instances
│   ├── ai_api.py            # AI analysis API (OpenAI, Anthropic, local models)
│   ├── analyzer.py          # Enhanced PCAP analyzer for web UI
│   └── templates/           # Jinja2 HTML templates (login, dashboard, project)
├── data/                    # SQLite database + project artifacts
└── logs/                    # JSON Lines logs (YYYY-MM-DD/)
```

**Data Flow:**
```
PCAP File → Scapy rdpcap() → Encryption detection (SSL ports + entropy > 0.8)
          → HL7 extraction (MSH| marker) → PII detection (Presidio + regex) → Results
```

**Database Models** (SQLite via SQLAlchemy in `web/database.py`):
- `User` — authentication, PBKDF2-SHA256 password hashing (600k iterations)
- `UserSession` — token-based sessions (24-hour expiry)
- `Project` — security audit workspace (owner_id enforces access control)
- `PcapAnalysis` — stored traffic analysis results (JSON)
- `ClientSession` — HL7 client interaction history
- `FuzzingJob` — fuzzer execution config + results
- `ServerInstance` — managed HL7 server instances

## Critical Patterns

### MLLP Protocol (Required for HL7 Transport)
```python
MLLP_START, MLLP_END = b'\x0b', b'\x1c\x0d'
mllp_wrapped = MLLP_START + hl7_msg.encode() + MLLP_END
```

### Binary Payload Decoding
```python
payload = pkt[Raw].load.decode('utf-8', errors='ignore')  # NEVER omit errors='ignore'
if 'MSH|' in payload:  # Always validate before parsing as HL7
```

### PII Detection
- HL7 PID segment parsing (score: 1.0) for structured data — fields PID-3 (MRN), PID-5 (Name), PID-7 (DOB), PID-11 (Address), PID-13/14 (Phone), PID-19 (SSN)
- Presidio NLP fallback for non-standard fields
- Analyzer instance is cached globally via `create_analyzer()` (Spacy model takes 2-5s to load)
- Deduplication uses (entity_type, value, timestamp) tuple

### Web API Authentication
```python
from .auth import require_auth
@router.get("/protected")
async def endpoint(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    # Enforce project ownership: Project.owner_id == user.id
```

All web APIs require authentication except `/auth/login`, `/auth/register`. The `require_auth` dependency raises 401 if not authenticated. Database sessions use `get_db` dependency injection.

## Key Constraints

1. Never hardcode config values—use `medaudit.config` module (`config.get_proxy_config()`, etc.)
2. Always validate `MSH|` marker before treating data as HL7
3. MLLP framing (`\x0b` start, `\x1c\x0d` end) is mandatory for HL7 device communication
4. Cache Presidio analyzer globally (Spacy `en_core_web_lg` is slow to initialize)
5. Log all errors with context, never let exceptions crash the program—skip malformed packets, return partial results
6. Project ownership is enforced—users can only access their own projects (`Project.owner_id == user.id`)
7. Use `errors='ignore'` when decoding binary payloads
8. Output limits: Max 10 HL7 messages, max 20 PII instances in CLI mode

## Configuration Precedence

CLI args → `medaudit/config/medaudit.json` → `./config/medaudit.json` → `./medaudit.json` → `~/.medaudit.json` → `~/.config/medaudit.json` → defaults

## Path Management

All paths use `medaudit/utils/paths.py` — directories are auto-created on module import:
- Database: `medaudit/data/medaudit.db`
- Artifacts: `medaudit/data/artifacts/projects/{id}/pcaps/`
- Logs: `medaudit/logs/YYYY-MM-DD/*.jsonl`
- Config: `medaudit/config/`

## Testing

Pytest config is in `tests/pytest.ini`. Shared fixtures (workspace_root, test_data_dir, sample_pcap) are in `tests/conftest.py`. Available markers: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.pcap`, `@pytest.mark.pii`, `@pytest.mark.slow`.

After PII changes: `pytest tests/test_pii_check.py -v`
After HL7 server changes: `pytest tests/test_hl7_server_client.py -v`
After PCAP logic changes: `python tests/analyze_pcap_pii.py`
