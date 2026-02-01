"""
Medaudit 2.0 Package - Medical Device Security Analysis Tool
AI Agent Instructions:
- Root package for Medaudit 2.0 (v2.0.0) - HL7/FHIR traffic analyzer
- Core subpackages: analysis, pii, proxy, hl7server, web, config, fuzzer
- Entry point: python -m medaudit [command] --help
- Available commands: analyze|proxy|web|config
- Configuration: Auto-loaded from medaudit/config/medaudit.json
- Database: SQLite at medaudit/data/medaudit.db
- Logs: JSON Lines format at medaudit/logs/YYYY-MM-DD/
- Data: Organized artifacts in medaudit/data/artifacts/
- Key features: PCAP analysis, PII detection, HTTP-HL7 proxy, HL7 fuzzer

## Testing
- Test Suite: Located at /tests/ (outside medaudit package)
- Test Files:
  * tests/test_pii_check.py - PII detection tests
  * tests/test_hl7_server_client.py - HL7 server/client integration
  * tests/test_logging_system.py - Logging functionality
  * tests/test_pii_on_pcap.py - PCAP analysis with PII
  * tests/analyze_pcap_pii.py - Manual PCAP analysis script
- Run Tests: pytest tests/ -v (or python -m pytest tests/)
- Test Data: medaudit/testFiles/*.pcap

## Project Structure (Centralized)
medaudit/
├── __init__.py                  # Package root + AI instructions
├── __main__.py                  # CLI dispatcher (analyze|proxy|web|config)
├── paths.py                     # Centralized path management
├── config/                      # Configuration module
│   ├── __init__.py             # Config class (loading from JSON)
│   ├── logging.py              # ProxyLogger, BaseJsonLogger
│   ├── medaudit.json           # Main configuration
│   └── hl7server.json          # HL7 server config
├── data/                       # Runtime data (inside package)
│   ├── medaudit.db            # SQLite database
│   └── artifacts/             # Project artifacts
│       └── projects/{id}/pcaps/
├── logs/                       # Runtime logs (inside package)
│   └── YYYY-MM-DD/            # Date-organized
│       ├── connections.jsonl
│       ├── server_events.jsonl
│       └── hl7_messages.jsonl
├── analysis/
│   ├── traffic/              # PCAP analysis, encryption detection
│   └── pii/                  # PII detection (Presidio + regex)
├── hl7server/               # Mock HL7 server (MLLP protocol)
├── proxy/                   # HTTP→HL7 proxy (Burp/ZAP compatible)
├── web/                     # FastAPI web platform
├── fuzzer/                  # HL7 fuzzing engine
└── testFiles/              # Sample PCAP files for testing
"""

__version__ = "2.0.0"
__author__ = "Medaudit Team"