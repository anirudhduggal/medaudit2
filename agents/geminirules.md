# .geminirules — Medaudit 2.0 for Google Gemini

## Project Overview
**Medaudit 2.0** is a medical device security analyzer for HL7/FHIR traffic. It detects encryption status, extracts HL7 v2.x messages, identifies PII exposure using Presidio NLP + regex hybrid patterns, and provides pentesting capabilities through a full-stack web UI, HTTP→HL7 proxy, mock/malicious HL7 servers, AI Co-Pilot Context Engine, and Model Context Protocol (MCP) server integration.

**Domain**: Healthcare IT Security | **Primary Focus**: PII Exposure & HL7/MLLP Protocol Vulnerability Assessment

---

## Quick Start (Gemini Context)

### Run Core Commands
```bash
# Analyze PCAP for encryption + PII
python3 -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap

# Start web UI (http://localhost:8000)
python3 -m medaudit web --password "mysecret" --port 8000

# Start Model Context Protocol (MCP) Server for AI Agents
python3 -m medaudit mcp

# Start mock HL7 server
python3 -m medaudit.hl7server start --port 2575

# Start HTTP→HL7 proxy (for Burp/ZAP)
python3 -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# Create user
python3 -m medaudit user --create --username analyst --password AnalystPass123 --full-name "Security Analyst"
```

---

## Architecture at a Glance

| Component | Purpose | Entry Point |
|-----------|---------|------------|
| **CLI Analyzer** | PCAP analysis, encryption detection, PII extraction | `medaudit/__main__.py` (analyze command) |
| **Web UI** | Project management, PCAP upload, real-time analysis dashboard | `medaudit/web/app.py` |
| **MCP Server** | Exposes FastMCP tools for AI pentest control & context retrieval | `medaudit/mcp_server.py` |
| **AI Context Engine** | Real-time state aggregator for AI Chat & Auto-Pentest | `medaudit/web/ai/context.py` |
| **Auto-Pentest Agent** | Semi-autonomous 7-stage HL7 vulnerability testing | `medaudit/web/ai/autopentest.py` |
| **HTTP→HL7 Proxy** | Security testing via Burp Suite/OWASP ZAP | `medaudit/proxy/proxy_server.py` |
| **Mock HL7 Server** | MLLP-compliant server for testing devices | `medaudit/hl7server/hl7_mock_server.py` |
| **HL7 Fuzzer** | Automated HL7 message mutation and attack simulation | `medaudit/fuzzer/cli.py` |
| **PII Detection Engine** | Presidio + regex hybrid detection | `medaudit/analysis/pii/pii_check.py` |

---

## Model Context Protocol (MCP) Tools

When connected via MCP (`python -m medaudit mcp`), Gemini can invoke:
1. `get_project_context(project_id)`: Fetches full project context, scan history, PCAP findings, PII exposures, and server logs.
2. `run_auto_pentest(project_id, target_host, ...)`: Launches context-aware semi-autonomous pentest runs.
3. `send_hl7_payload(target_host, target_port, message)`: Dispatches MLLP payloads and logs activity to `ContextEngine`.
4. `start_mock_server` / `stop_mock_server`: Controls mock MLLP servers.
5. `start_fuzzer`: Launches protocol mutation jobs.
6. `analyze_pcap`: Detailed PCAP parsing, encryption heuristics, and PII identification.

---

## Key Concepts & Guidelines for Gemini

### 1. HL7 v2.x & MLLP Protocol
- **Format**: Pipe-delimited segments (`MSH`, `PID`, `PV1`) with subcomponents.
- **MLLP Framing**: Start byte `\x0b`, End bytes `\x1c\r`. Unencrypted TCP.
- **Binary Safety**: Always use `errors='ignore'` when decoding raw payloads.

### 2. Encryption Detection Heuristics
- **SSL/TLS Ports**: 443, 993, 995, 465, 587, 8443 → assumed encrypted.
- **Entropy Analysis**: Payload entropy > 0.8 → likely encrypted.

### 3. Dual-State Awareness
- Server and Proxy instances are tracked both in-memory (`_active_servers`, `active_proxies`) and in the SQLite database (`ServerInstance`).
- Always check both live state and database state to prevent state mismatches after web server restarts.

### 4. Encrypted Credentials
- AI provider API keys are encrypted at rest using local AES-256-GCM keyfile protection (`medaudit/data/.secret_key` with `0600` permissions).
