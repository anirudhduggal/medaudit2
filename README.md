# Medaudit 2.0

Medaudit 2.0 is a comprehensive tool designed to assist pentesters, auditors, and enthusiasts in pentesting and analyzing medical devices in a controlled environment. It focuses on HL7 2.x and FHIR protocols, providing capabilities for traffic analysis, proxying, and fuzzing to ensure the security and integrity of medical device communications.

## Features

### ✅ Currently Implemented

#### 1. Traffic Analysis & PII Detection
- **Input**: Wireshark PCAP trace files
- **Encryption Analysis**: Determines if traffic is fully encrypted, partially encrypted, or unencrypted using heuristic methods (SSL ports + payload entropy analysis)
- **HL7 Message Detection**: Identifies HL7 v2.x messages starting with "MSH|" in unencrypted traffic
- **PII Detection**: Scans for sensitive information including:
  - Credit card numbers (validated with Luhn algorithm)
  - Names, addresses, and payment methods
  - Financial keywords and patterns
- **Output**: Clear reports on encryption status and detected sensitive data

#### 2. HTTP-to-HL7 Proxy
- **Purpose**: Convert HTTP requests to HL7 messages for testing medical devices with proxy tools like Burp Suite or OWASP ZAP
- **Functionality**: HTTP server that receives POST requests, wraps content in HL7 format, and forwards to HL7 server
- **Protocol**: Uses MLLP (Minimal Lower Layer Protocol) for HL7 transport
- **Usage**: Compatible with Burp Suite, ZAP, and other HTTP proxy tools

### 🚧 Planned Features (Future Releases)

#### 2. HL7 Proxy
- Acts as a proxy for HL7 traffic
- Enables integration with popular tools like Burp Suite or OWASP ZAP
- Allows interception and modification of HL7 messages for testing purposes

#### 3. HL7 Fuzzer (Client Mode)
- Provides basic fuzzing strings and capabilities
- Tests medical devices by sending malformed or unexpected HL7 traffic
- Helps identify vulnerabilities in device parsing and handling

#### 4. HL7 Fuzzer (Server Mode)
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
│   ├── analysis/            # Traffic analysis module
│   │   ├── __init__.py      # Exports analysis functions
│   │   └── traffic_analysis.py  # PCAP parsing, encryption detection, HL7 extraction
│   ├── pii/                 # PII detection module
│   │   ├── __init__.py      # Exports PII detection functions
│   │   └── pii_check.py     # Credit card, name, address, financial detection
│   ├── proxy/               # HTTP-to-HL7 proxy module
│   │   ├── __init__.py      # Exports proxy functions
│   │   └── proxy_server.py # HTTP server that converts requests to HL7
│   └── testFiles/           # Test PCAP files for development
│       └── hl7_v2_unencrypted_synthetic.pcap
├── venv/                    # Virtual environment (created during setup)
├── .gitignore              # Git ignore rules for Python projects
├── requirements.txt         # Python dependencies
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

4. (Optional) Install additional tools like Burp Suite or OWASP ZAP for proxy functionality

## Usage

### Traffic Analysis (Currently Implemented)
```bash
python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap
```

This will analyze the PCAP file and:
- Determine if traffic is **fully encrypted**, **partially encrypted**, or **unencrypted**
- Extract and parse **HL7 messages** from unencrypted traffic
- Detect **PII** including:
  - Credit card numbers (with Luhn validation)
  - Names, addresses, payment methods
  - Financial keywords and patterns

#### Example Output:
```
Traffic is fully unencrypted.

Unencrypted packets: 1

Detected PII instances: 3
  Potential Address: 123 FAKE ST
  Potential Address: 5
  Potential Address: 0100
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

## Configuration

Medaudit 2.0 supports configuration files for default settings:

### Configuration File
Create a `medaudit.json` file in the current directory or `~/.medaudit.json`:

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

- **Modular Design**: Separate packages for analysis (`medaudit.analysis`) and PII detection (`medaudit.pii`)
- **AI-Friendly Code**: Each module includes docstring instructions for AI agents on how to use and extend the code
- **Clear Separation**: Traffic parsing, encryption detection, HL7 extraction, and PII scanning are in separate modules
- **Extensible**: Easy to add new analysis features or PII detection patterns

## Configuration

Medaudit 2.0 currently uses default settings. Future versions will support configuration files for custom settings.

## Development & Testing

### Test Files
The project includes test PCAP files for development and validation:
- `medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap` - Sample unencrypted HL7 traffic

### Running Tests
```bash
# Test with the included sample file
python -m medaudit medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap

# Test with your own PCAP files
python -m medaudit path/to/your/file.pcap
```

### Code Quality
- Modular architecture with clear separation of concerns
- AI agent instructions embedded in docstrings for better code understanding
- Comprehensive `.gitignore` to keep repository clean
- Virtual environment setup for consistent development

## Contributing

We welcome contributions! The codebase is designed to be extensible:

1. **Analysis Features**: Add new traffic analysis capabilities in `medaudit/analysis/`
2. **PII Detection**: Extend PII patterns in `medaudit/pii/pii_check.py`
3. **New Modules**: Follow the modular structure for new features

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