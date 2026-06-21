# CLAUDE.md - Quick Reference for Developers

This file is a quick reference for working with Medaudit 2.0. For comprehensive AI agent guidelines, project architecture, and constraints, see [copilot-instructions.md](copilot-instructions.md).

## Project Overview

**Medaudit 2.0** is a medical device security analyzer for HL7 v2.x and FHIR traffic. It provides PCAP traffic analysis, PII detection (Presidio NLP + regex), HTTP-to-HL7 proxying for Burp/ZAP integration, mock HL7 servers, HL7 fuzzing, and a full-stack FastAPI web UI with authentication.

## Quick Setup

```bash
# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg  # Required one-time download (~500MB)

# Start the web UI
python -m medaudit web --generate-password  # Generate secure admin password
# Access at http://localhost:8080
```

## Essential Commands

```bash
# Web UI
python -m medaudit web --host 0.0.0.0 --port 8080

# CLI Analysis
python -m medaudit analyze <file.pcap>

# HTTP-to-HL7 Proxy (for Burp/ZAP)
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# HL7 Mock Server
python -m medaudit.hl7server start --port 2575

# HL7 Fuzzer
python -m medaudit.fuzzer run -c config.yaml -o results.json
python -m medaudit.fuzzer test --host localhost --port 2575
python -m medaudit.fuzzer server --mode no_ack --port 2575  # Malicious server modes
python -m medaudit.fuzzer attacks  # List all attack modes

# User management
python -m medaudit user --create --username john --password pass123

# Configuration
python -m medaudit config --show
python -m medaudit config --create

# Tests
pytest tests/ -v                      # All tests
pytest tests/test_pii_check.py -v    # PII detection
pytest tests/test_hl7_server_client.py -v  # HL7 server/client
python tests/analyze_pcap_pii.py      # Manual pipeline test
```

## Project Structure

| Location | Purpose |
|----------|---------|
| `medaudit/__main__.py` | CLI dispatcher (analyze, web, proxy, config, user) |
| `medaudit/analysis/` | PCAP parsing, encryption detection, HL7 extraction, PII detection |
| `medaudit/proxy/` | HTTP→MLLP converter for Burp/ZAP |
| `medaudit/hl7server/` | Standalone MLLP server + client library |
| `medaudit/fuzzer/` | HL7 fuzzing engine with 17 attack modes |
| `medaudit/web/` | FastAPI platform with authentication, project management, analysis APIs |
| `medaudit/utils/paths.py` | Centralized path management (data, config, logs) |
| `medaudit/config/` | Configuration files (medaudit.json, hl7server.json) |
| `medaudit/data/` | SQLite database, project artifacts |
| `medaudit/logs/` | JSON Lines logs (organized by date) |

## Database

SQLite database with tables for:
- `User` — authentication, PBKDF2-SHA256 hashing
- `UserSession` — token-based sessions (24-hour expiry)
- `Project` — security audit workspaces
- `PcapAnalysis` — traffic analysis results
- `ClientSession` — HL7 client history
- `FuzzingJob` — fuzzer execution + results
- `ServerInstance` — managed HL7 servers

## Testing

After making changes:
- PII detection: `pytest tests/test_pii_check.py -v`
- HL7 server: `pytest tests/test_hl7_server_client.py -v`
- AI API: `pytest tests/test_ai_api.py -v`
- All tests: `pytest -q`

## Key Resources

| File | Purpose |
|------|---------|
| [copilot-instructions.md](copilot-instructions.md) | **Comprehensive AI agent guidelines, architecture, patterns, constraints** |
| [README.md](README.md) | Project overview, features, quick start |
| [docs/](docs/) | Implementation guides (AI, Registration, Fuzzing Logs, etc.) |

## Common Tasks

### Adding a New Web API
1. Create endpoint in appropriate module under `medaudit/web/` (e.g., `traffic_api.py`, `client_api.py`)
2. Protect with `@require_auth` dependency
3. Enforce project ownership: `Project.owner_id == user.id`
4. Return `HTTPException` for errors, never crash

### Analyzing a PCAP
1. Extract HL7 messages (validate `MSH|` marker)
2. Detect encryption (SSL ports + entropy > 0.8)
3. Parse PII using HL7 PID segment (preferred) + Presidio NLP fallback
4. Return results including summary, findings, connections

### Running HL7 Fuzzer
1. Create YAML config (templates available)
2. Specify mutation strategies (field, segment, delimiter mutations)
3. Logs saved to `medaudit/data/fuzzing_logs/{project_id}/{job_id}/`
4. Download traffic logs from web UI

### Testing HL7 Server
1. Start server: `python -m medaudit.hl7server start --port 2575`
2. Send message: `python -m medaudit.fuzzer test --host localhost --port 2575`
3. Check logs: `medaudit/logs/YYYY-MM-DD/`

## Configuration Precedence

CLI args → `medaudit/config/medaudit.json` → `~/.medaudit.json` → defaults

---

**Note**: For comprehensive architectural details, critical code patterns (MLLP protocol, binary decoding, PII detection), error handling conventions, and AI agent responsibilities, see [copilot-instructions.md](copilot-instructions.md).
