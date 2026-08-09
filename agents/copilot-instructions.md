# Medaudit 2.0 — AI Agent & Co-Pilot Instructions

Medical device security analyzer for HL7/FHIR traffic. Detects encryption status, extracts HL7 v2.x messages, identifies PII exposure using Presidio NLP + regex patterns. Features a full-stack web UI with authentication, project management, HL7 client/fuzzer, traffic analysis with visualization, Model Context Protocol (MCP) server, AI Pentest Co-Pilot, and PDF/JSON export.

**Quick Reference**: See [CLAUDE.md](CLAUDE.md) for a concise developer quick-start guide with essential commands and project structure.


## Current Status & Capabilities

### Core AI & Pentest Subsystems
1. **Context Engine (`medaudit/web/ai/context.py`)**:
   - Collects real-time state across all modules: `Project` metadata, `ServerInstance` connection/message logs, `FuzzingJob` findings, `PcapAnalysis` PII exposures, and recent activity.
   - Automatically builds comprehensive system prompt context for AI Chat (`POST /api/ai/chat`) and Auto-Pentesting (`POST /api/ai/auto-pentest/start`).
   - Encrypted API Key Storage: AI credentials (OpenAI, Anthropic, Gemini, Ollama) are persisted to the database encrypted at rest using local AES-256-GCM keyfile protection (`medaudit/data/.secret_key` with `0600` permissions).

2. **Model Context Protocol (MCP) Server (`medaudit/mcp_server.py`)**:
   - Built-in FastMCP server (`python -m medaudit mcp`) exposing 7 primary tools to external LLM clients (Claude Desktop, Cursor, Custom Agents):
     - `get_project_context(project_id)`: Fetches full project context, scan history, PCAP findings, PII exposures, and server logs.
     - `run_auto_pentest(project_id, target_host, ...)`: Launches context-aware semi-autonomous penetration test runs.
     - `send_hl7_payload(target_host, target_port, message)`: Dispatches MLLP payloads and logs activity to `ContextEngine`.
     - `start_mock_server` / `stop_mock_server`: Controls mock MLLP servers.
     - `start_fuzzer`: Launches protocol mutation jobs.
     - `analyze_pcap`: Detailed PCAP parsing, encryption heuristics, and PII identification.

3. **Semi-Autonomous Auto-Pentest Agent (`medaudit/web/ai/autopentest.py`)**:
   - 7-Stage Pentest Methodology: `recon` -> `fuzz` -> `sqli` -> `crash` -> `pii` -> `exploit` (GATED) -> `report`.
   - Incorporates prior PCAP traffic findings and previous fuzzer results into LLM attack approach narration.
   - Enforces target authorization validation (`confirm_target=True` required for remote non-loopback targets).

4. **HTTP-to-MLLP Proxy & Burp Extension (`medaudit/proxy/proxy_server.py`)**:
   - Converts HTTP POST payloads into MLLP-wrapped HL7 messages for Burp Suite/OWASP ZAP integration.
   - Burp Suite Java extension source provided under `burp-extension/`. Build with `cd burp-extension && gradle jar`.
   - Web UI management endpoint (`POST /api/proxy/start`) launches UTF-8 validated background processes with startup verification.

---

## Agent Responsibilities

This document is intended for AI-assisted development agents (Copilot/Code Assistant) working on the `medaudit` codebase. Agents should follow these rules when editing, testing, or documenting the project:

- **Safety First**: Never output or suggest real patient data. Use synthetic or redacted examples in docs and tests.
- **Use Centralized Paths**: Prefer `medaudit.paths` helpers for any filesystem locations (data, logs, artifacts).
- **Dual-State Handling**: When working on server/proxy code, check both in-memory state and database state before changing statuses.
- **Non-destructive Edits**: Make minimal, focused code changes. Do not reformat unrelated files or change public APIs without explicit user approval.
- **Testing**: Run relevant tests after changes (`pytest tests/<target> -q`) and fix only failures introduced by your edits.
- **Logging and Errors**: Log errors with context, and return safe defaults; do not crash the process on malformed inputs.
- **Documentation**: Update `README.md` and `docs/` whenever behavior or CLI usage changes. Link to this instruction file from the top-level README.
- **Config Precedence**: Respect the configuration override order (CLI args -> medaudit/config/medaudit.json -> user config locations).

---

## Architecture Overview

```
medaudit/
├── __main__.py                        # CLI dispatcher (analyze|web|proxy|config|fuzzer|user|mcp)
├── mcp_server.py                      # FastMCP server exposing tool definitions
├── utils/
│   └── paths.py                       # Centralized path management (data, config, logs)
├── analysis/
│   ├── traffic/traffic_analysis.py    # PCAP parsing, encryption heuristics, HL7 extraction
│   └── pii/pii_check.py               # Presidio analyzer + custom recognizers
├── proxy/proxy_server.py              # HTTP→HL7 converter for Burp/ZAP testing
├── hl7server/
│   ├── hl7_mock_server.py             # MLLP-compliant mock server with ACK responses
│   ├── hl7_client.py                  # HL7 client for sending messages
│   ├── message_logger.py              # JSON Lines message logging
│   └── cli.py                         # HL7 server CLI interface
├── fuzzer/                            # Dedicated Medical Device Fuzzer Module
│   ├── strategies.py                  # Mutation strategies (field, segment, delimiter, overflow, injection)
│   ├── engine.py                      # Fuzzing execution engine + message generation
│   ├── protocol.py                    # HL7/MLLP protocol handling
│   └── malicious_hl7_server.py        # Malicious HL7 server (17 attack modes)
├── web/
│   ├── app.py                         # FastAPI main app + page routes
│   ├── auth.py                        # User authentication + registration + session management
│   ├── database.py                    # SQLAlchemy models (User, Project, Analysis, AICredential, etc.)
│   ├── server_api.py                  # Managed HL7 server instances
│   ├── proxy_api.py                   # HTTP→MLLP proxy management
│   ├── ai_api.py                      # AI Analysis API & Auto-Pentest endpoints
│   ├── ai/
│   │   ├── context.py                 # ContextEngine state aggregator
│   │   ├── autopentest.py             # Semi-autonomous pentest engine
│   │   ├── providers.py               # LLM provider implementations (OpenAI, Anthropic, Gemini, Ollama)
│   │   └── prompts.py                 # System prompts
│   └── templates/                     # Jinja2 HTML templates
├── burp-extension/                    # Java Montoya API Burp extension source (build via `gradle jar`)
└── data/                              # SQLite database, encryption keyfile (.secret_key), artifacts
```

---

## Essential Commands

```bash
# Start Web UI Platform
python -m medaudit web --password "mysecret" --port 8000
python -m medaudit web --generate-password --port 8080

# Standalone CLI Analysis
python -m medaudit analyze path/to/capture.pcap

# Start MCP Server for AI Agents
python -m medaudit mcp

# HTTP→HL7 Proxy (Security Testing)
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# HL7 Mock Server (Standalone)
python -m medaudit.hl7server start --port 2575

# Malicious HL7 Server (Robustness & DoS Testing)
python -m medaudit.fuzzer server --mode no_ack --port 2575
python -m medaudit.fuzzer attacks  # List all 17 attack modes

# Burp Extension Compilation
cd burp-extension && gradle jar

# Run Test Suite
pytest tests/ -v
```

---

## Key Constraints for AI Assistants

1. **Binary Decoding Safety**: Always use `errors='ignore'` when decoding raw TCP/MLLP payloads.
2. **HL7 Protocol Validation**: Always verify the `MSH|` marker before attempting HL7 segment parsing.
3. **MLLP Transport**: MLLP framing (`\x0b` start byte, `\x1c\r` end bytes) is mandatory for HL7 communication.
4. **Presidio Caching**: Cache the Spacy NLP model instance globally to avoid 10x startup slowdowns.
5. **Dual-State Synchronization**: Check both in-memory dictionaries (`_active_servers`, `active_proxies`) and database tables (`ServerInstance`, `Project`).
6. **Authentication & Access Control**: All web endpoints (except login/register) require `@require_auth` and enforce project ownership (`Project.owner_id == user.id`).
