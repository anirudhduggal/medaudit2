# .windsurfrules — Medaudit 2.0 Development Guidelines

## Project Identity
Medical device security analyzer for HL7/FHIR traffic with PCAP analysis, real-time web UI, HTTP→HL7 proxy, mock/malicious HL7 servers, AI Co-Pilot Context Engine, and Model Context Protocol (MCP) server integration.

## Quick Navigation
- **Start Web UI**: `python -m medaudit web --password "mysecret" --port 8000`
- **Start MCP Server**: `python -m medaudit mcp`
- **Analyze PCAP**: `python -m medaudit analyze <file.pcap>`
- **Proxy**: `python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575`
- **HL7 Mock Server**: `python -m medaudit.hl7server start --port 2575`
- **Build Burp Extension**: `cd burp-extension && gradle jar`

## Key Code Locations
| Task | File |
|------|------|
| FastMCP AI tools | `medaudit/mcp_server.py` |
| AI Context Engine | `medaudit/web/ai/context.py` |
| Auto-Pentest Agent | `medaudit/web/ai/autopentest.py` |
| PCAP analysis logic | `medaudit/analysis/traffic/traffic_analysis.py` |
| PII detection | `medaudit/analysis/pii/pii_check.py` |
| HTTP→HL7 proxy | `medaudit/proxy/proxy_server.py` |
| Web API & routes | `medaudit/web/app.py` & `medaudit/web/*_api.py` |
| Mock HL7 server | `medaudit/hl7server/hl7_mock_server.py` |
| CLI dispatcher | `medaudit/__main__.py` |

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

### Auto-Pentest Workflow
```
Recon (baseline MLLP ACK) → Fuzz (field mutations) → SQLi Oracle → Crash (oversized PID-5)
  → PII Exposure Scan → Exploit (Stored-XSS, Gated) → Executive Report
```

### MCP Tool Access
- `get_project_context(project_id)`: Fetches project history, PCAPs, PII findings, and logs.
- `run_auto_pentest(project_id, target_host)`: Launches semi-autonomous pentest.
- `send_hl7_payload(target_host, target_port, message)`: Dispatches MLLP payload and updates context.
- `start_mock_server` / `stop_mock_server` / `start_fuzzer` / `analyze_pcap`.

## Coding Standards

### Binary Decoding & Protocol Handling
- Always use `errors='ignore'` when decoding raw binary TCP/MLLP payloads.
- Always check for `MSH|` marker before parsing HL7.
- MLLP framing (`\x0b` start, `\x1c\r` end) is mandatory for HL7 device communication.

### Dual-State Management
- Check both in-memory state (`_active_servers`, `active_proxies`) and database models (`ServerInstance`, `Project`).

### Security
- Admin password required on Web UI startup (`--password` or `--generate-password`).
- AI provider keys encrypted at rest using local keyfile (`medaudit/data/.secret_key` with 0600 permissions).

## Testing
- Run test suite: `pytest tests/ -v`
