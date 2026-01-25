# Medaudit 2.0

Medaudit 2.0 is a comprehensive tool designed to assist pentesters, auditors, and enthusiasts in pentesting and analyzing medical devices in a controlled environment. It focuses on HL7 2.x and FHIR protocols, providing capabilities for traffic analysis, proxying, and fuzzing to ensure the security and integrity of medical device communications.

## Features

### 1. Traffic Analysis
- **Input**: Unencrypted Wireshark trace files
- **Analysis**: Examines HL7 2.x and FHIR traffic for:
  - Personally Identifiable Information (PII)
  - Device information
  - End-to-end encryption status
- **Purpose**: Helps determine if the network has proper encryption in place

### 2. HL7 Proxy
- Acts as a proxy for HL7 traffic
- Enables integration with popular tools like Burp Suite or OWASP ZAP
- Allows interception and modification of HL7 messages for testing purposes

### 3. HL7 Fuzzer (Client Mode)
- Provides basic fuzzing strings and capabilities
- Tests medical devices by sending malformed or unexpected HL7 traffic
- Helps identify vulnerabilities in device parsing and handling

### 4. HL7 Fuzzer (Server Mode)
- Acts as an HL7 server
- Sends out fuzzed traffic to test client resilience
- Simulates malicious server behavior to assess client-side security

## Project Structure
```
medaudit2/
├── medaudit/
│   ├── __init__.py          # Package initialization
│   ├── __main__.py          # Main entry point
│   ├── analysis/            # Traffic analysis module
│   │   ├── __init__.py
│   │   └── traffic_analysis.py
│   └── pii/                 # PII detection module
│       ├── __init__.py
│       └── pii_check.py
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Installation

### Prerequisites
- Python 3.8 or higher
- Wireshark (for trace analysis)
- Burp Suite or OWASP ZAP (for proxy functionality)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/medaudit2.git
   cd medaudit2
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Install additional tools if needed

## Usage

### Traffic Analysis
```bash
python -m medaudit path/to/wireshark_trace.pcap
```

This will analyze the PCAP file and:
- Determine if traffic is fully encrypted, partially encrypted, or unencrypted
- If partially or fully unencrypted, extract and parse for HL7 messages and PII (names, addresses, financial information including credit cards, payment methods)

### Proxy Mode
```bash
python medaudit.py proxy --port 8080 --target hl7-server:2575
```

### Client Fuzzer
```bash
python medaudit.py fuzz client --target hl7-server:2575 --fuzz-strings fuzz_payloads.txt
```

### Server Fuzzer
```bash
python medaudit.py fuzz server --port 2575 --fuzz-mode aggressive
```

For detailed usage instructions and options, run:
```bash
python medaudit.py --help
```

## Configuration

Medaudit 2.0 supports configuration files for custom settings. See `config.example.yaml` for available options.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on how to get started.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Medaudit 2.0 is intended for educational and security research purposes only. Use responsibly and only on systems you have permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## Support

For questions, issues, or contributions, please open an issue on our GitHub repository.