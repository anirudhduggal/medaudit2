# CLAUDE.md - Quick Reference for AI Assistants & Developers

This document provides concise context, commands, and architecture for Claude and other LLM assistants working with human penetration testers on **Medaudit 2.0**.

## Project Overview

**Medaudit 2.0** is a medical device security auditing platform for HL7 v2.x and FHIR protocols. It features PCAP traffic analysis, PII exposure detection (Presidio NLP + regex), HTTP-to-HL7 proxying for Burp Suite/ZAP integration, mock & malicious HL7 servers, automated protocol fuzzing, an AI-powered pentest co-pilot, and Model Context Protocol (MCP) server support.

---

## Essential Commands

```bash
# Web UI Platform
python -m medaudit web --password "mysecret" --port 8000
python -m medaudit web --generate-password --port 8080

# Standalone CLI PCAP Analysis
python -m medaudit analyze path/to/capture.pcap

# Model Context Protocol (MCP) Server for AI Agents
python -m medaudit mcp

# HTTP-to-HL7 Proxy (for Burp Suite / OWASP ZAP)
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# HL7 Mock Server (MLLP ACK generator)
python -m medaudit.hl7server start --port 2575

# HL7 Malicious Server (Robustness / Denial-of-Service Testing)
python -m medaudit.fuzzer server --mode no_ack --port 2575
python -m medaudit.fuzzer attacks  # List all 17 attack modes

# Burp Extension Compilation
cd burp-extension && gradle jar  # Output: build/libs/medaudit2-burp-extension-1.0.0.jar

# Run Full Test Suite
pytest tests/ -v
```

---

## AI Assistant Capabilities & Architecture

### 1. Context Engine (`medaudit/web/ai/context.py`)
Aggregates real-time state from all modules into prompt context for AI Chat (`POST /api/ai/chat`) and Auto-Pentesting:
- **Project Metadata**: Name, description, total scans & server status.
- **HL7 Servers**: Active server instances, live connection stats, and recent MLLP message logs.
- **Fuzzing Jobs**: Active/historical fuzzing runs, total mutations, and severity-ranked findings.
- **PCAP Traffic Analysis**: PII exposure entities (names, SSNs, DOBs), encryption heuristics (entropy > 0.8), and message type counts.
- **Client & Proxy History**: Payloads sent, responses received, and error patterns.
- **Auto-Pentest Agent Results**: Summary of previous semi-autonomous pentest runs.

### 2. Model Context Protocol (MCP) Server (`medaudit/mcp_server.py`)
Medaudit runs a FastMCP server (`python -m medaudit mcp`) allowing external LLMs (Claude Desktop, Cursor, Custom Agents) to control pentests:
- `get_project_context(project_id)`: Retrieve full project state, scan findings, PII exposures, and logs.
- `run_auto_pentest(project_id, target_host, ...)`: Launch context-aware semi-autonomous pentests.
- `send_hl7_payload(target_host, target_port, message)`: Dispatch HL7 payloads and log events to `ContextEngine`.
- `start_mock_server` / `stop_mock_server`: Manage mock MLLP servers.
- `start_fuzzer`: Run automated HL7 protocol mutation jobs.
- `analyze_pcap`: Detailed PCAP parsing, encryption heuristics, and PII identification.

### 3. Semi-Autonomous Auto-Pentest Agent (`medaudit/web/ai/autopentest.py`)
Deterministic 7-stage HL7 penetration testing methodology:
1. `recon`: Baseline MLLP connectivity & transport check.
2. `fuzz`: Automated HL7 field mutation strategies.
3. `sqli`: Deterministic single-quote SQL injection oracle.
4. `crash`: Oversized PID-5 robustness / DoS probe.
5. `pii`: PHI/PII transit exposure scan.
6. `exploit`: Stored-XSS payload execution (GATED — requires operator confirmation).
7. `report`: Executive summary & HIPAA risk reporting.

*Safety Guard*: Non-loopback target engagements enforce authorization validation (`confirm_target=True`).

### 4. Encrypted AI Credentials
AI provider API keys (OpenAI, Anthropic, Gemini, Ollama) are persisted to the database encrypted at rest using local AES-256-GCM keyfile protection (`medaudit/data/.secret_key` with `0600` permissions).

---

## Project Structure Overview

| Location | Purpose |
|----------|---------|
| `medaudit/__main__.py` | CLI entry point (analyze, web, proxy, config, user, mcp) |
| `medaudit/mcp_server.py` | FastMCP server exposing tools for AI agents |
| `medaudit/analysis/` | Scapy PCAP parsing, encryption heuristics, Presidio PII NLP engine |
| `medaudit/proxy/` | HTTP-to-MLLP converter for Burp/ZAP integration |
| `medaudit/hl7server/` | MLLP mock server & client libraries |
| `medaudit/fuzzer/` | HL7 mutation strategies, execution engine, malicious HL7 servers |
| `medaudit/web/` | FastAPI web UI, authentication, database ORM, AI context engine |
| `medaudit/web/ai/` | `context.py` (Context Engine), `autopentest.py` (Auto-Pentest Agent), `providers.py` |
| `burp-extension/` | Java Montoya API extension for Burp Suite (build with `gradle jar`) |

---

## Assisting Human Pentesters

When assisting human penetration testers with Medaudit 2.0:
1. **Target Verification**: Ensure the target host & MLLP port (`2575` default) are reachable and authorized.
2. **Proxy Setup**: Use `python -m medaudit proxy --port 8080 --hl7-port 2575` or the Web UI Proxy tab to intercept and modify HL7 traffic in Burp Suite.
3. **Contextual Guidance**: Use `ContextEngine` data (or `get_project_context` in MCP) to examine detected PII fields and prior fuzzer findings before suggesting targeted attack payloads.
4. **Safety Compliance**: Never leak real patient data; recommend synthetic ADT/ORM/ORU HL7 messages for testing.
