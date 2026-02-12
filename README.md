# Medaudit 2.0 - Medical Device Security Analyzer

**Version**: 2.0.0 | **Status**: ✅ Production Ready | **Last Updated**: February 1, 2026

**Agent Instructions**: Development agents and contributors should read the project-specific agent guidance in `.github/copilot-instructions.md` before making edits.

Medaudit 2.0 is a comprehensive security analysis tool for HL7 v2.x and FHIR medical device communications. It provides PCAP traffic analysis, PII detection, HTTP-to-HL7 proxying, and a mock HL7 server for pentesting medical devices in controlled environments.

---

## 🎯 Core Features

### 1. PCAP Traffic Analysis & PII Detection
**Analyze network traffic captures for encryption status and sensitive data exposure**

- ✅ **Encryption Detection**: SSL port analysis + Shannon entropy heuristics
- ✅ **HL7 v2.x Parsing**: MLLP protocol (0x0B/0x1C0D) message extraction
- ✅ **PII Detection**: Microsoft Presidio NLP + regex patterns
  - Healthcare entities: PERSON, PATIENT_ID, MEDICAL_RECORD_NUMBER
  - Financial: CREDIT_CARD (Luhn validated), BANK_NUMBER, ROUTING_NUMBER
  - Personal: SSN, PHONE_NUMBER, EMAIL, ADDRESS, DATE_OF_BIRTH
  - Locations: Street addresses, cities, zip codes
- ✅ **Comprehensive Reporting**: Traffic classification, HL7 messages, PII instances

**Quick Start:**
```bash
python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
```

**Output:**
```
Traffic is fully unencrypted.
Unencrypted packets: 1

Detected PII instances: 3
  PERSON: John Doe (score: 1.0)
  PATIENT_ID: 12345 (score: 1.0)
  PHONE_NUMBER: 555-0100 (score: 0.85)
```

---

### 2. Mock HL7 2.x Server
**MLLP-compliant HL7 server for testing and development**

- ✅ **Full MLLP Protocol**: Start byte (0x0B), end bytes (0x1C0D)
- ✅ **Automatic ACK Responses**: AA (Application Accept) messages
- ✅ **Multi-threaded**: Handles concurrent client connections
- ✅ **Comprehensive Logging**: JSON Lines format with date organization
- ✅ **Configurable**: Persistent settings via `medaudit/config/hl7server.json`

**Usage:**
```bash
# Start server on port 2575
python -m medaudit.hl7server start --port 2575

# Start with custom host
python -m medaudit.hl7server start --host 0.0.0.0 --port 2576

# Show server configuration
python -m medaudit.hl7server config --show

# Create default configuration file
python -m medaudit.hl7server config --create
```

**Features:**
- Logs stored in `medaudit/logs/YYYY-MM-DD/`
- Message tracking with timestamps
- Connection event logging
- Graceful shutdown support

---

### 3. HL7 Client Library
**Send HL7 messages programmatically or via CLI**

- ✅ **Message Builders**: ADT (patient admit/discharge), ORM (orders), ORU (results), MDM (documents)
- ✅ **MLLP Protocol**: Automatic framing with start/end bytes
- ✅ **Connection Management**: Connect, send, disconnect with error handling
- ✅ **Timeout Support**: Configurable timeouts for reliability

**Programmatic Usage:**
```python
from medaudit.hl7server import HL7Client

# Create client
client = HL7Client(host='localhost', port=2575)

# Send ADT message
response = client.send_adt_message(
    patient_id='12345',
    patient_name='John^Doe',
    event_type='A01'  # Admit
)
print(response)

# Close connection
client.disconnect()
```

---

### 4. HTTP-to-HL7 Proxy
**Integrate medical device testing with Burp Suite, OWASP ZAP, or other HTTP tools**

- ✅ **HTTP → MLLP Conversion**: Automatic protocol wrapping
- ✅ **Burp Suite Compatible**: Use HTTP Repeater for HL7 testing
- ✅ **Comprehensive Logging**: HTTP requests, conversions, HL7 responses, errors
- ✅ **Remote Device Support**: Forward to external medical device servers

**Usage:**
```bash
# Terminal 1: Start HL7 server (for testing)
python -m medaudit.hl7server start --port 2575

# Terminal 2: Start proxy
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# Terminal 3: Send HTTP request
curl -X POST http://localhost:8080/ \
  -d "MSH|^~\&|SEND|FAC|RECV|FAC|20260201||ADT^A01|001|P|2.5"
```

**Logs:** `medaudit/logs/proxy_activity.jsonl`

---

### 5. Web UI Platform
**Full-featured web interface for comprehensive security auditing**

- ✅ **User Authentication**: Secure session-based authentication with PBKDF2 password hashing
- ✅ **User Registration**: Self-service account creation with tabbed login/register interface
- ✅ **Project Management**: Create and manage security audit projects
- ✅ **HL7 Client**: Interactive client with malformed payload library (buffer overflow, SQLi, XSS, etc.)
- ✅ **HL7 Fuzzer**: Web-based fuzzer with YAML/JSON rule configuration
- ✅ **Traffic Analysis**: PCAP upload with network visualization and sequence diagrams
- ✅ **Server Management**: Create and manage multiple HL7 server instances

**Getting Started:**

New users can register directly from the login page using the "Register" tab.

**Default Admin Credentials** (for initial setup):
```
Username: admin
Password: admin123
```

⚠️ **IMPORTANT**: Change the default admin password immediately after first login!

**Usage:**
```bash
# Start with default credentials
python -m medaudit web

# Start with custom password
python -m medaudit web --password "SecurePassword123!"

# Start with auto-generated secure password
python -m medaudit web --generate-password

# Specify host and port
python -m medaudit web --host 0.0.0.0 --port 8080
```

**Access:**
- Web UI: http://lauthentication (protection against brute force)
- 👤 Self-service user registration with email validation
- API Docs: http://localhost:8080/docs

**Features:**
- 📊 Dashboard with project overview
- 🔐 Rate-limited login (protection against brute force)
- 🧪 Built-in malformed payload library for testing
- 📈 Traffic visualization with Cytoscape.js
- 📄 PDF report generation
- 🔄 Session management (24-hour expiry)
- 🤖 **AI-Powered Analysis** - Ask questions, brainstorm pentesting strategies, and get security recommendations using OpenAI, Anthropic Claude, or local models (Ollama/LM Studio). The AI has access to **comprehensive project context** including all traffic logs, PCAP data, HL7 messages, PII findings, fuzzing results, and server logs.

**Documentation:**
- 🔐 [Admin Credentials & Security](docs/ADMIN_CREDENTIALS.md)
- 🤖 [AI Analysis Guide](docs/AI_ANALYSIS_GUIDE.md) - Full feature documentation
- 🚀 [AI Quick Start](docs/AI_QUICK_START.md) - Get started in 5 minutes
- 📊 [AI Context Guide](docs/AI_CONTEXT_GUIDE.md) - Understanding data exposure
- 📝 [Default Admin Implementation](docs/DEFAULT_ADMIN_IMPLEMENTATION.md)

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/medaudit2.git
cd medaudit2

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download Spacy model for PII detection (one-time, ~500MB)
python -m spacy download en_core_web_lg
```

### Verify Installation

```bash
# Check CLI
python -m medaudit --help

# Run tests
cd tests && pytest -v

# Analyze sample PCAP
python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
```

---

## 📖 Usage Guide

### Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `analyze` | Analyze PCAP file | `python -m medaudit analyze <file.pcap>` |
| `web` | Start web UI platform | `python -m medaudit web --port 8080` |
| `proxy` | Start HTTP-to-HL7 proxy | `python -m medaudit proxy --port 8080` |
| `config` | Manage configuration | `python -m medaudit config --show` |
| `user` | Create user (local admin) | `python -m medaudit user --create --username john --password pass123` |
| `hl7server start` | Start HL7 server | `python -m medaudit.hl7server start --port 2575` |
| `hl7server config` | Configure HL7 server | `python -m medaudit.hl7server config --show` |
| `fuzzer run` | Run HL7 fuzzer | `python -m medaudit.fuzzer run -c config.yaml` |

### Configuration

Configuration files use JSON format and are auto-loaded from:
1. `medaudit/config/medaudit.json` (preferred)
2. `~/.medaudit.json` (user home)
3. `~/.config/medaudit.json` (XDG config)

**Sample `medaudit/config/medaudit.json`:**
```json
{
  "proxy": {
    "http_host": "0.0.0.0",
    "http_port": 8080,
    "hl7_host": "localhost",
    "hl7_port": 2575
  },
  "analysis": {
    "max_hl7_messages": 10,
    "max_pii_instances": 20
  },
  "logging": {
    "enabled": true,
    "log_dir": "logs"
  }
}
```

**Create default config:**
```bash
python -m medaudit config --create
```

---

## 📁 Project Structure

```
medaudit2/
├── medaudit/                      # Main package (all runtime data inside)
│   ├── __init__.py                # Package metadata + AI instructions
│   ├── __main__.py                # CLI dispatcher (analyze|web|proxy|config|fuzzer)
│   │
│   ├── utils/                     # Utilities and helpers
│   │   └── paths.py               # Centralized path management
│   │
│   ├── config/                    # Configuration module
│   │   ├── __init__.py            # Config class (JSON loading)
│   │   ├── logging.py             # ProxyLogger, BaseJsonLogger
│   │   ├── medaudit.json          # Main configuration
│   │   └── hl7server.json         # HL7 server settings
│   │
│   ├── data/                      # Runtime data (inside package)
│   │   ├── medaudit.db            # SQLite database
│   │   └── artifacts/             # Project artifacts (PCAPs, exports)
│   │       └── projects/{id}/pcaps/
│   │
│   ├── logs/                      # Runtime logs (inside package)
│   │   └── YYYY-MM-DD/            # Date-organized JSON Lines logs
│   │       ├── connections.jsonl
│   │       ├── server_events.jsonl
│   │       ├── hl7_messages.jsonl
│   │       └── proxy_activity.jsonl
│   │
│   ├── analysis/                  # Traffic & PII analysis
│   │   ├── traffic/               # PCAP parsing, encryption detection
│   │   │   └── traffic_analysis.py
│   │   └── pii/                   # PII detection (Presidio + regex)
│   │       └── pii_check.py
│   │
│   ├── hl7server/                 # Mock HL7 server
│   │   ├── hl7_mock_server.py     # MLLP server implementation
│   │   ├── hl7_client.py          # HL7 client library
│   │   ├── message_logger.py      # JSON Lines logging
│   │   └── cli.py                 # HL7 server CLI
│   │
│   ├── proxy/                     # HTTP→HL7 proxy
│   │   └── proxy_server.py        # HTTP server + MLLP conversion
│   │
│   ├── fuzzer/                    # HL7 Fuzzer
│   │   ├── __main__.py            # Fuzzer CLI entry point
│   │   ├── cli.py                 # Fuzzer commands
│   │   ├── engine.py              # Fuzzing execution engine
│   │   ├── strategies.py          # Mutation strategies
│   │   ├── protocol.py            # HL7/MLLP protocol handling
│   │   └── malicious_hl7_server.py # Attack server (17 modes)
│   │
│   ├── web/                       # Web UI Platform
│   │   ├── app.py                 # FastAPI main app + routes
│   │   ├── auth.py                # Authentication + session management
│   │   ├── database.py            # SQLAlchemy models (User, Project, etc.)
│   │   ├── projects.py            # Project CRUD API
│   │   ├── client_api.py          # HL7 Client API + malformed payloads
│   │   ├── fuzzer_api.py          # Fuzzer Web API
│   │   ├── traffic_api.py         # PCAP analysis + visualization
│   │   ├── server_api.py          # Managed HL7 server instances
│   │   ├── ai_api.py              # AI Analysis API (NEW)
│   │   └── templates/             # Jinja2 HTML templates
│   │       └── project.html       # Project view with AI tab
│   │
│   └── testFiles/                 # Sample PCAP files
│       ├── hl7_v2_unencrypted_synthetic.pcap
│       └── hl7_v2_unencrypted_synthetic_no_pii.pcap
│
├── docs/                          # Documentation
│   ├── README.md                  # Documentation index
│   ├── AI_ANALYSIS_GUIDE.md       # Complete AI feature guide
│   ├── AI_QUICK_START.md          # 5-minute AI setup guide
│   ├── AI_CONTEXT_GUIDE.md        # AI data access documentation
│   ├── ADMIN_CREDENTIALS.md       # Admin security guide
│   └── DEFAULT_ADMIN_IMPLEMENTATION.md
│
├── tests/                         # Test suite
│   ├── pytest.ini                 # Pytest configuration
│   ├── conftest.py                # Shared fixtures
│   ├── test_pii_check.py          # PII detection tests
│   ├── test_ai_api.py             # AI API tests
│   ├── test_hl7_server_client.py  # HL7 integration tests
│   ├── test_admin_creation.py     # Admin user tests
│   ├── verify_ai_feature.py       # AI feature verification
│   └── results/                   # Test reports
│
├── pcap-samples/                  # Sample traffic captures
├── requirements.txt               # Python dependencies
├── README.md                      # This file
└── .gitignore
```

---

## 🧪 Testing

### Run Tests

```bash
# All tests (run from project root)
cd tests && pytest -v

# Or from project root
pytest tests/ -v

# Specific test file
pytest tests/test_pii_check.py -v

# With coverage (if pytest-cov installed)
pytest tests/ --cov=medaudit --cov-report=html

# Quick test (quiet mode)
cd tests && pytest -q
```

### Test Results
```
======================== 4 passed, 4 warnings in 3.23s =========================
✅ test_detect_pii_with_presidio PASSED
✅ test_detect_pii_credit_card_with_presidio PASSED
✅ test_detect_pii_no_pii PASSED
✅ test_logging PASSED
```

### Test Configuration
- **Location**: `tests/pytest.ini`
- **Fixtures**: `tests/conftest.py` (shared test utilities)
- **Markers**: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.pcap`

---

## 🏗️ Architecture

### Data Flow
```
PCAP File
    ↓
Scapy.rdpcap() → Load packets
    ↓
Packet Classification (SSL ports + entropy analysis)
    ↓
HL7 Detection (MSH| marker + MLLP framing)
    ↓
PII Detection (Presidio NLP + Regex patterns)
    ↓
Results Report (JSON format)
```

### Key Technologies
| Technology | Purpose | Version |
|------------|---------|---------|
| **Scapy** | PCAP parsing & packet analysis | ≥2.7.0 |
| **Presidio** | NLP-based PII detection | ≥2.2.360 |
| **Spacy** | Natural language processing | ≥3.8.0 |
| **FastAPI** | Web framework (planned) | ≥0.128.0 |
| **SQLAlchemy** | Database ORM (planned) | ≥2.1.0 |

### Centralized Path Management
All runtime data uses `medaudit/utils/paths.py`:
- **Config**: `medaudit/config/`
- **Data**: `medaudit/data/` (database + artifacts)
- **Logs**: `medaudit/logs/YYYY-MM-DD/`

Benefits: Package encapsulation, simple distribution, clean root directory

---

## 🚧 Planned Features (Future Releases)

### Enhanced Web Platform
- 🔲 Two-factor authentication (2FA)
- 🔲 User role management (viewer, analyst, admin)
- 🔲 Real-time collaboration features
- 🔲 Advanced analytics dashboard
- 🔲 Custom report templates

### Advanced Fuzzing
- 🔲 Genetic algorithm-based fuzzing
- 🔲 Coverage-guided fuzzing
- 🔲 Crash analysis and deduplication
- 🔲 Automated regression testing

### FHIR Support
- 🔲 FHIR R4 message parsing
- 🔲 FHIR-specific PII detection
- 🔲 FHIR REST API security testing

---

## ⚡ Performance Notes

| Operation | First Call | Subsequent Calls |
|-----------|-----------|------------------|
| **Spacy Model Load** | 2-5 seconds | Cached (instant) |
| **PII Detection** | 100-500ms/payload | After model load |
| **PCAP Analysis** | 1-3s per 1MB file | Depends on packet count |

**Memory Usage:**
- Spacy model: ~100MB loaded in memory
- PCAP: Full file loaded (no streaming)
- Typical workspace: <500MB (including database)

---

## 🛠️ Troubleshooting

### Spacy Model Issues
```bash
# Model download fails
python -m spacy download en_core_web_lg --upgrade

# Verify model installed
python -c "import spacy; spacy.load('en_core_web_lg')"
```

### Port Already in Use
```bash
# Find process using port
lsof -i :2575

# Kill process
kill -9 <PID>
```

### Import Errors
```bash
# Ensure virtual environment active
source venv/bin/activate

# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

### Configuration Not Loading
```bash
# Check config search paths
python -c "from medaudit.paths import get_config_search_paths; print(get_config_search_paths())"

# Create default config
python -m medaudit config --create
```

---

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow existing code patterns
4. Add tests for new functionality
5. Update AI instructions in module docstrings
6. Submit a pull request

### Development Guidelines
- **Code Style**: PEP 8, type hints preferred
- **Testing**: Unit tests required for new features
- **Documentation**: Docstrings with AI-friendly explanations
- **Logging**: Use centralized `medaudit.config.logging` module

---

## 📝 AI Agent Instructions

Medaudit 2.0 includes comprehensive AI agent instructions throughout the codebase:

### Module-Level Instructions
Each module has detailed docstrings explaining:
- Purpose and functionality
- Key functions and their signatures  
- Dependencies and imports
- Common usage patterns
- Error handling approach

**Key Modules:**
- `medaudit/__init__.py` - Package overview, project structure, testing info
- `medaudit/analysis/traffic/traffic_analysis.py` - PCAP parsing workflow
- `medaudit/analysis/pii/pii_check.py` - PII detection methods
- `medaudit/proxy/proxy_server.py` - HTTP-to-HL7 conversion
- `medaudit/hl7server/hl7_mock_server.py` - MLLP server implementation

### For AI Developers
- All public functions have detailed docstrings
- Error handling patterns are consistent
- Configuration is centralized
- Test files demonstrate expected behavior

---

## ⚠️ Disclaimer

**Medaudit 2.0 is intended for educational and authorized security research purposes only.**

- Use responsibly and only on systems you have explicit permission to test
- The authors are not responsible for any misuse or damage caused by this tool
- Always comply with applicable laws and regulations
- Medical device testing should follow proper regulatory guidelines

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 📞 Support & Contact

- **Issues**: [GitHub Issue Tracker](https://github.com/yourusername/medaudit2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/medaudit2/discussions)
- **Documentation**: This README + module docstrings
- **Email**: [Your contact email]

---

**Version**: 2.0.0  
**Last Updated**: February 1, 2026  
**Status**: ✅ **Production Ready** (Core Features)

*Built for security professionals, auditors, and researchers working with medical device communications.*
