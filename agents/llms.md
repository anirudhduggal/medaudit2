# llms.txt — Medaudit 2.0 AI Instructions

## System Context
Medaudit 2.0 is a Python-based medical device security auditing tool for analyzing HL7/FHIR traffic, detecting encryption status, extracting HL7 v2.x messages, identifying PII in unencrypted communications, and running automated penetration testing via Web UI, CLI, or Model Context Protocol (MCP).

## Quick Start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m spacy download en_core_web_lg
python3 -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
python3 -m medaudit web --password "mysecret" --port 8000
python3 -m medaudit mcp
```

## Architecture Overview
```
Input (PCAP / HTTP / MCP) → Parsing & Decoupling → Encryption / PII / Fuzzing Oracles → ContextEngine → Report / UI
```

### Key Modules
- **mcp_server.py** → FastMCP server exposing tools (`get_project_context`, `run_auto_pentest`, `send_hl7_payload`, `start_fuzzer`, `analyze_pcap`)
- **web/ai/context.py** → Real-time state aggregator feeding prompt context to AI Chat & Auto-Pentest
- **web/ai/autopentest.py** → Semi-autonomous 7-stage HL7 pentesting agent
- **analysis/traffic/** → PCAP parsing, encryption heuristic, HL7 detection
- **analysis/pii/** → Presidio analyzer + regex patterns for entities
- **proxy/** → HTTP to MLLP-wrapped HL7 converter
- **hl7server/** → Mock HL7 2.x server with ACK generation
- **fuzzer/** → Protocol mutation strategies and 17 malicious server attack modes
- **web/** → FastAPI UI with authentication, database persistence, and analysis APIs

## Critical Patterns
- **Binary Decoding**: Always use `errors='ignore'` for raw TCP payload decoding
- **HL7 Protocol**: Format `MSH|^~\\&|...`; MLLP framing `\x0b` (start) + message + `\x1c\r` (end)
- **Encryption Detection**: SSL/TLS ports (443, 993, 995, 8443) or entropy > 0.8
- **PII Detection**: Hybrid dual-mode (Structured HL7 PID fields + Presidio NLP with cached Spacy model)
- **Dual-State Sync**: Check both in-memory dicts (`_active_servers`, `active_proxies`) and database state
- **Encrypted Credentials**: AI API keys encrypted at rest via AES-256-GCM (`medaudit/data/.secret_key` with 0600 permissions)
