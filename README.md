# Medaudit 2.0

Medaudit 2.0 is a comprehensive tool designed to assist pentesters, auditors, and enthusiasts in pentesting and analyzing medical devices in a controlled environment. It focuses on HL7 2.x and FHIR protocols, providing capabilities for traffic analysis, proxying, and fuzzing to ensure the security and integrity of medical device communications.

## Features

### ✅ Currently Implemented

#### 1. Mock HL7 2.x Server
- **Purpose**: Simulates real medical device HL7 servers for testing and security analysis
- **Functionality**: Accepts MLLP-wrapped HL7 messages, generates ACK responses
- **Encryption**: Optional TLS/SSL support (disabled by default for open testing)
- **Logging**: Comprehensive message logging to structured JSON files with date organization
- **CLI**: Command-line interface for easy server startup and configuration
- **Features**:
  - Multi-threaded client handling with configurable timeouts
  - MLLP protocol compliance (0x0B frame start, 0x1C0D frame end)
  - JSON Lines logging with separate files for messages, connections, and events
  - Configuration file support for persistent settings

#### 2. Traffic Analysis & PII Detection
- **Input**: Wireshark PCAP trace files
- **Encryption Analysis**: Determines if traffic is fully encrypted, partially encrypted, or unencrypted using heuristic methods (SSL ports + payload entropy analysis)
- **HL7 Message Detection**: Identifies HL7 v2.x messages starting with "MSH|" in unencrypted traffic
- **PII Detection**: Scans for sensitive information using:
  - **Presidio Analyzer**: Microsoft's NLP-based PII detection engine for entity recognition (names, addresses, phone numbers, etc.)
  - **Pattern Matching**: Credit card numbers (validated with Luhn algorithm), SSN, financial keywords
  - **Regex Patterns**: Address and phone number detection
  - **Comprehensive Coverage**: Credit cards, names, addresses, payment methods, and financial patterns
- **Output**: Clear reports on encryption status and detected sensitive data with entity types

#### 3. HTTP-to-HL7 Proxy
- **Purpose**: Convert HTTP requests to HL7 messages for testing medical devices with proxy tools like Burp Suite or OWASP ZAP
- **Functionality**: HTTP server that receives POST requests, wraps content in HL7 format, and forwards to HL7 server
- **Protocol**: Uses MLLP (Minimal Lower Layer Protocol) for HL7 transport
- **Usage**: Compatible with Burp Suite, ZAP, and other HTTP proxy tools

### 🚧 Planned Features (Future Releases)

#### HL7 Fuzzer (Client Mode)
- Provides basic fuzzing strings and capabilities
- Tests medical devices by sending malformed or unexpected HL7 traffic
- Helps identify vulnerabilities in device parsing and handling

#### HL7 Fuzzer (Server Mode)
- Acts as an HL7 server
- Sends out fuzzed traffic to test client resilience
- Simulates malicious server behavior to assess client-side security

## Project Structure
```
medaudit2/
├── medaudit/                # Main Python package
│   ├── __init__.py          # Package initialization with version info
│   ├── __main__.py          # Main entry point for `python -m medaudit`
│   ├── config.py            # Configuration file handling
│   ├── analysis/            # Analysis module with submodules
│   │   ├── __init__.py      # Unified exports from all analysis submodules
│   │   ├── traffic/         # Traffic analysis submodule
│   │   │   ├── __init__.py  # Exports traffic analysis functions
│   │   │   └── traffic_analysis.py  # PCAP parsing, encryption detection, HL7 extraction
│   │   └── pii/             # PII analysis submodule
│   │       ├── __init__.py  # Exports PII detection functions
│   │       └── pii_check.py # Credit card, name, address, financial detection
│   ├── proxy/               # HTTP-to-HL7 proxy module
│   │   ├── __init__.py      # Exports proxy functions
│   │   └── proxy_server.py  # HTTP server that converts requests to HL7
│   ├── hl7server/           # Mock HL7 2.x server module
│   │   ├── __init__.py      # Exports server components
│   │   ├── __main__.py      # CLI entry point
│   │   ├── hl7_mock_server.py   # Core HL7 server implementation
│   │   ├── hl7_client.py    # HL7 client library with message generators
│   │   ├── message_logger.py # Comprehensive message logging system
│   │   ├── server_config.py # Configuration management for server
│   │   └── cli.py           # Command-line interface
│   ├── logging.py           # Proxy activity logging system
│   └── testFiles/           # Test PCAP files for development
│       ├── hl7_v2_unencrypted_synthetic.pcap
│       └── hl7_v2_unencrypted_synthetic_no_pii.pcap
├── tests/                   # Test suite and results
│   ├── test_*.py            # Test scripts (unit tests, integration tests)
│   ├── test_hl7_server_client.py   # HL7 server/client integration test
│   ├── test_comprehensive_hl7.py   # Comprehensive HL7 test suite
│   ├── analyze_pcap_pii.py  # PCAP analysis script
│   ├── results/             # Test execution results and reports
│   ├── logs/                # Proxy activity logs (date-organized) [in .gitignore]
│   └── fixtures/            # Test data and fixtures
├── .github/                 # GitHub configuration
│   └── copilot-instructions.md  # AI agent instructions
├── venv/                    # Virtual environment (created during setup)
├── .gitignore              # Git ignore rules for Python projects
├── requirements.txt         # Python dependencies
├── config/medaudit.json    # Configuration file (preferred location)
└── README.md               # This file
```

## Installation

### Prerequisites
- Python 3.8 or higher
- Wireshark (for trace analysis)
- Git (for cloning the repository)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/medaudit2.git
   cd medaudit2
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Download the Spacy NLP model required for Presidio PII detection:
   ```bash
   python -m spacy download en_core_web_lg
   ```

5. (Optional) Install additional tools like Burp Suite or OWASP ZAP for proxy functionality

### PII Detection with Presidio

Medaudit 2.0 uses **Microsoft Presidio** for advanced PII detection:
- **Presidio Analyzer**: NLP-based entity recognition using Spacy NER
- **Supported Entities**: PERSON, PHONE_NUMBER, EMAIL_ADDRESS, SSN, CREDIT_CARD, LOCATION, etc.
- **Configurable**: Custom entity types and recognizers can be added
- **Notes**: Presidio's accuracy depends on the trained NLP model; medical device data formats may require entity mapping tuning

## Usage

### Mock HL7 2.x Server (Currently Implemented)
```bash
# Start server with default settings (localhost:2575, non-encrypted)
python -m medaudit.hl7server start

# Start on custom port with custom HL7 message log directory
python -m medaudit.hl7server start --port 2576 --log-dir /var/log/hl7

# Create default configuration file
python -m medaudit.hl7server config --create

# Show current configuration
python -m medaudit.hl7server config --show
```

**Features:**
- Multi-threaded server accepts concurrent client connections
- Generates HL7 ACK responses for each received message
- Logs all messages, connections, and events to structured JSON files
- Date-organized log directories (logs/YYYY-MM-DD/)
- Per-message tracking with timestamps and metadata

**Example Usage with HL7 Client:**
```python
from medaudit.hl7server import HL7Client

# Send ADT (Admission/Discharge/Transfer) message
client = HL7Client(host="localhost", port=2575)
client.connect()
ack = client.send_adt_message()  # Send pre-built ADT^A01 message
print(ack)  # Print ACK response
client.disconnect()
```

### Traffic Analysis (Currently Implemented)
```bash
python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
```

This will analyze the PCAP file and:
- Determine if traffic is **fully encrypted**, **partially encrypted**, or **unencrypted**
- Extract and parse **HL7 messages** from unencrypted traffic
- Detect **PII** using multiple methods:
  - **Presidio Analyzer**: NLP-based entity recognition (requires `en_core_web_lg` model)
  - **Pattern Matching**: Credit card numbers with Luhn validation, SSN patterns
  - **Regex Patterns**: Address and phone number detection
  - **Healthcare Context**: Detects names, IDs, and other PII in HL7 message formats

#### Example Output:
```
Traffic is fully unencrypted.

Unencrypted packets: 1

Detected PII instances: 3
  PERSON: John Doe
  PATIENT_ID: 123456
  PHONE_NUMBER: 555-0100
```

### HTTP-to-HL7 Proxy (Currently Implemented)
```bash
# Start proxy with default config
python -m medaudit proxy

# Start proxy on custom ports
python -m medaudit proxy --port 9090 --hl7-host 192.168.1.100 --hl7-port 2576

# Forward to remote medical device server
python -m medaudit proxy --hl7-host medical-device.company.com --hl7-port 2575
```

This starts an HTTP server that:
- Listens for HTTP POST requests on the specified port
- Converts request bodies to HL7 messages wrapped in MLLP
- Forwards messages to the target HL7 server
- Returns HL7 responses as HTTP responses
- **Logs all activities** to date-organized folders when enabled (HTTP requests, HL7 conversions, responses, and errors)

#### Logging Features:
- **Date-organized folders**: Logs saved in `logs/YYYY-MM-DD/` format
- **JSON Lines format**: Structured logging in `.jsonl` files for easy parsing
- **Comprehensive tracking**: All HTTP requests, HL7 conversions, responses, and errors logged
- **Configurable**: Enable/disable logging and set custom log directory via configuration
- **Audit trail**: Complete record of proxy operations for debugging and compliance

#### Example Log Entry:
```json
{"timestamp": "2024-01-15T10:30:45.123456", "event_type": "http_request", "method": "POST", "path": "/", "content_length": 256, "client_ip": "127.0.0.1"}
{"timestamp": "2024-01-15T10:30:45.234567", "event_type": "hl7_conversion", "original_length": 256, "hl7_length": 280, "hl7_message_start": "MSH|^~\\&|..."}
{"timestamp": "2024-01-15T10:30:45.345678", "event_type": "hl7_response", "status": "success", "response_length": 512, "hl7_ack": "MSA|AA|..."}
```

## Configuration

Medaudit 2.0 supports configuration files for default settings:

### Configuration File
Create a `config/medaudit.json` file in the project root (preferred) or `medaudit.json` in the current directory or `~/.medaudit.json` for compatibility:

```json
{
  "proxy": {
    "http_host": "localhost",
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

### Configuration Commands
```bash
# Create default configuration file
python -m medaudit config --create

# Show current configuration
python -m medaudit config --show
```

Command line arguments override configuration file settings.

#### Usage with Burp Suite:
1. Start the proxy: `python -m medaudit proxy`
2. Configure Burp Suite to use upstream proxy at `localhost:8080`
3. Send HTTP requests through Burp to target medical devices
4. Requests are automatically converted to HL7 format

### Future Features (Not Yet Implemented)
The following features are planned for future releases:

#### HL7 Fuzzer (Client Mode)
```bash
# Planned: python -m medaudit fuzz client --target hl7-server:2575 --fuzz-strings fuzz_payloads.txt
```

#### HL7 Fuzzer (Server Mode)
```bash
# Planned: python -m medaudit fuzz server --port 2575 --fuzz-mode aggressive
```

## Architecture & AI Agent Instructions

Medaudit 2.0 is designed with a modular architecture and includes AI agent instructions throughout the codebase:

- **Modular Design**: Analysis package with submodules for traffic (`medaudit.analysis.traffic`) and PII detection (`medaudit.analysis.pii`)
- **AI-Friendly Code**: Each module includes docstring instructions for AI agents on how to use and extend the code
- **Clear Separation**: Traffic parsing, encryption detection, HL7 extraction, and PII scanning are organized in submodules
- **Extensible**: Easy to add new analysis submodules following the established pattern

## Development & Testing

### Test Structure
The project organizes all test-related files under the `tests/` directory:
- `test_pii_check.py` - Unit tests for PII detection functionality
- `test_comprehensive.py` - Tests for core Medaudit 2.0 components (config, logging, traffic analysis)
- `test_comprehensive_hl7.py` - Comprehensive test suite for HL7 server/client components
- `test_hl7_server_client.py` - Integration test: HL7 server and client message exchange
- `test_logging_system.py` - Tests for proxy logging system
- `test_pii_on_pcap.py` - PCAP PII detection and extraction testing
- `analyze_pcap_pii.py` - Analysis script for PCAP PII research
- `results/` - Test execution results and analysis reports
- `logs/` - Proxy and server activity logs (date-organized, in .gitignore)
- `fixtures/` - Test data and fixtures

### Test Data
The project includes test PCAP files for development and validation:
- `medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap` - Sample unencrypted HL7 traffic

### Running Tests
```bash
# Test with the included sample file
python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap

# Test core components
python tests/test_comprehensive.py

# Test HL7 server components
python tests/test_comprehensive_hl7.py

# Test HL7 server and client integration
python tests/test_hl7_server_client.py

# Run unit tests for PII detection
pytest tests/test_pii_check.py

# Analyze PCAP for PII extraction
python tests/analyze_pcap_pii.py

# Test with your own PCAP files
python -m medaudit analyze path/to/your/file.pcap
```

### Code Quality
- Modular architecture with clear separation of concerns
- AI agent instructions embedded in docstrings for better code understanding
- Comprehensive `.gitignore` to keep repository clean
- Virtual environment setup for consistent development

## Code Quality & Analysis

### Code Analysis Report

#### Duplicate Test Files ⚠️
The project contains overlapping test files that should be consolidated:

**Status**: Tests are organized but show some duplication in coverage

1. **test_comprehensive.py** (229 lines)
   - Tests core Medaudit 2.0 components: config, logging, traffic analysis, PCAP parsing
   - **Functions**: `test_imports()`, `test_config()`, `test_logging()`, `test_traffic_analysis()`, `test_pcap_analysis()`, `test_proxy_server()`

2. **test_comprehensive_hl7.py** (311 lines)
   - Tests HL7 server components: imports, config, server startup, client connection, message sending, logging output, MLLP protocol
   - **Functions**: `test_imports()`, `test_server_config()`, `test_server_startup()`, `test_client_connection()`, `test_message_sending()`, `test_logging_output()`, `test_mllp_protocol()`

3. **test_hl7_server_client.py** (165 lines)
   - Integration test: runs server and sends various HL7 message types
   - **Functions**: `run_server()`, `run_client_tests()` (5 message types: ADT, ORM, ORU, MDM)

4. **Other Test Files**:
   - `test_pii_check.py` - Dedicated PII detection tests (no duplication)
   - `test_logging_system.py` - Dedicated logging system tests (no duplication)
   - `test_pii_on_pcap.py` - PCAP PII extraction analysis (no duplication)
   - `analyze_pcap_pii.py` - Analysis script (not a test)

**Recommendation**: Test organization is clean:
- `tests/test_comprehensive.py` - Core Medaudit component tests
- `tests/test_comprehensive_hl7.py` - HL7 server component tests
- `tests/test_hl7_server_client.py` - Integration tests

#### Code Duplication Analysis ✅
**Finding**: Minimal code duplication detected. Architecture is well-modularized.

**Key Observations**:
- **Configuration handling**: Well-abstracted in `medaudit.config.Config` class and `medaudit.hl7server.server_config.ServerConfig` - separate concerns, no duplication
- **Logging systems**: Two distinct loggers serve different purposes:
  - `medaudit.logging.ProxyLogger` - HTTP-to-HL7 proxy activity logging (6+ months old)
  - `medaudit.hl7server.message_logger.MessageLogger` - HL7 server message logging (recent)
  - Could potentially share base class for common JSON file operations
- **HL7 message parsing**: Centralized in `traffic_analysis.py`, properly imported by PII detection
- **Import organization**: Good use of `__init__.py` files for unified exports

**Minor Opportunity**:
Create shared `medaudit.logging.BaseJsonLogger` to reduce duplication between ProxyLogger and MessageLogger:
```python
# Current pattern (both implement independently):
- ProxyLogger._write_log_entry()
- MessageLogger._write_to_jsonl()
# Both do similar JSON serialization + date-organized file creation
```

#### Dead Code Analysis ✅
**Finding**: No significant dead code detected.

**Code Organization**:
- All imports are used
- All functions have documented purposes
- No unreachable code blocks
- No commented-out test code
- Redundant test files have been removed

#### Unused Imports ✅
**Finding**: Clean imports throughout codebase. No unused imports detected.

**Best Practices**:
- Modules properly import only what they need
- Submodule `__init__.py` files cleanly export public APIs
- Internal imports are organized and meaningful

### Recommendations Summary

**Completed** ✅:
1. Consolidated test files and removed redundant `test_client.py`
2. Removed duplicate `test_message_logger` function
3. Pinned dependency versions in requirements.txt

**Medium Priority** (Architecture improvement):
1. Create shared `BaseJsonLogger` class to reduce duplication between proxy and HL7 server logging
2. Add type hints to function signatures for better IDE support

**Low Priority** (Documentation):
1. Add architecture diagram to README showing module dependencies
2. Document logging system architecture (two separate systems serving different purposes)

**Current State**: ✅ Well-organized, minimal duplication, clean code structure

## Contributing

We welcome contributions! The codebase is designed to be extensible:

1. **Analysis Features**: Add new traffic analysis capabilities in `medaudit/analysis/`
2. **PII Detection**: Extend PII patterns in `medaudit/analysis/pii/pii_check.py`
3. **Proxy Features**: Enhance HTTP-to-HL7 conversion in `medaudit/proxy/proxy_server.py`
4. **HL7 Server**: Extend mock server capabilities in `medaudit/hl7server/hl7_mock_server.py` or add new message types to `medaudit/hl7server/hl7_client.py`
5. **Test Coverage**: Add new tests following existing patterns in `tests/`

### Code Quality Guidelines
- Follow existing code organization and module structure
- Add docstrings to all functions and classes
- Include AI agent instructions in module docstrings
- Keep test files organized and avoid duplication
- Use type hints where practical for better IDE support
- Maintain consistent formatting and naming conventions

### Development Setup
```bash
git clone https://github.com/yourusername/medaudit2.git
cd medaudit2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Medaudit 2.0 is intended for educational and security research purposes only. Use responsibly and only on systems you have permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## Support

For questions, issues, or contributions, please open an issue on our GitHub repository.