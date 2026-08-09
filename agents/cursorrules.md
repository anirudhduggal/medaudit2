# .cursorrules — Medaudit 2.0 Development Rules

## Project Context
Medical device security analyzer for HL7/FHIR traffic. Features PCAP parsing, Presidio PII NLP, HTTP→HL7 proxy, MLLP mock/malicious servers, FastMCP server, AI Pentest Co-Pilot, and FastAPI web UI.

## Core Entry Points
- `medaudit/__main__.py` — CLI dispatcher (analyze, web, proxy, config, hl7server, fuzzer, mcp)
- `medaudit/mcp_server.py` — FastMCP server exposing pentest tools for AI agents
- `medaudit/web/ai/context.py` — ContextEngine aggregating real-time project state
- `medaudit/web/ai/autopentest.py` — Semi-autonomous HL7 penetration testing engine
- `medaudit/analysis/` — PCAP parsing & PII detection
- `medaudit/proxy/proxy_server.py` — HTTP→HL7 converter
- `medaudit/hl7server/hl7_mock_server.py` — MLLP server

## Coding Rules

### HL7 & MLLP Handling
- Always check for `MSH|` marker before parsing HL7 messages
- Use MLLP framing: `\x0b` (start) + message + `\x1c\r` (end)
- Remove MLLP wrapper before parsing: strip `\x0b`, split on `\x1c`
- Use `errors='ignore'` when decoding binary payloads (UTF-8 safety)

### Encryption & PII Detection
- SSL ports (443, 993, 995, 465, 587, 8443) or entropy > 0.8 = encrypted
- Use Presidio `AnalyzerEngine` with Spacy `en_core_web_lg` model (cached globally)
- Fallback regex for credit cards (Luhn), SSN, phone, addresses

### MCP & AI Pentesting
- FastMCP tools (`get_project_context`, `run_auto_pentest`, `send_hl7_payload`, `start_mock_server`, `start_fuzzer`, `analyze_pcap`).
- Auto-Pentest 7-stage pipeline (`recon`, `fuzz`, `sqli`, `crash`, `pii`, `exploit`, `report`).
- Target authorization safety check enforced (`confirm_target=True` for non-loopback targets).

### Credentials & Config
- AI API keys stored encrypted at rest via AES-256-GCM using `medaudit/data/.secret_key` (0600 permissions).
- Load precedence: CLI args -> config/medaudit.json -> ~/.medaudit.json -> defaults.

### Dual-State & Logging
- Check both in-memory dicts (`_active_servers`, `active_proxies`) and database tables before altering statuses.
- JSON Lines logs in `medaudit/logs/YYYY-MM-DD/`.

### Testing
- Run test suite: `pytest tests/ -v`
