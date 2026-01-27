# Medaudit 2.0 - AI Agent Instructions

## Project Overview
Medaudit 2.0 analyzes medical device network traffic for security auditing and provides HTTP-to-HL7 proxy functionality. It processes PCAP files to detect encryption status, extract HL7 v2.x messages, and identify personally identifiable information (PII) in unencrypted traffic. The proxy enables testing medical devices with tools like Burp Suite by converting HTTP requests to HL7 messages.

## Architecture
- **Modular packages**: `medaudit.analysis` for traffic parsing, `medaudit.pii` for sensitive data detection, `medaudit.proxy` for HTTP-to-HL7 conversion
- **Entry point**: `python -m medaudit analyze <pcap_file>` for analysis, `python -m medaudit proxy` for proxy server
- **Data flow**: PCAP → scapy parsing → encryption heuristics → HL7 detection ("MSH|" prefix) → PII scanning; HTTP → HL7 conversion → MLLP wrapping → target device

## Key Workflows
- **Analysis**: Run `python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap` for testing
- **Proxy**: Run `python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575` to start HTTP-to-HL7 proxy
- **Remote Proxy**: Use `--hl7-host <remote_ip>` and `--hl7-port <port>` to forward to external medical devices
- **Configuration**: Create `medaudit.json` for default settings, use `python -m medaudit config --create`
- **Extension**: Add analysis features in `medaudit/analysis/`, PII patterns in `medaudit/pii/pii_check.py`, proxy features in `medaudit/proxy/`
- **Testing**: Use synthetic PCAP files in `medaudit/testFiles/` for development validation

## Code Patterns
- **Encryption detection**: Heuristic approach using SSL ports (443, 993, 995, 465, 587) + payload entropy (>0.8 ratio)
- **HL7 identification**: Check for "MSH|" prefix in decoded UTF-8 payload
- **HL7 conversion**: Wrap messages in MLLP format (`\x0b{message}\x1c\r`) for transport
- **PII validation**: Credit cards use Luhn algorithm; regex patterns for names (`[A-Z][a-z]+\s[A-Z][a-z]+`), addresses (`\d+\s+[A-Za-z0-9\s,.-]+`)
- **Error handling**: Decode payloads with `errors='ignore'` to handle binary data gracefully
- **Output limiting**: Show first 10 HL7 messages, 20 PII instances to prevent console overflow

## Dependencies & Integration
- **Core library**: scapy for PCAP parsing (`from scapy.all import rdpcap, TCP, UDP, Raw`)
- **Input format**: Wireshark PCAP files with Ethernet frames; HTTP POST requests for proxy
- **Output**: Console reports with encryption ratios, HL7 headers, PII classifications; HL7 responses converted back to HTTP
- **Extension points**: Modular design allows adding new detection modules following `medaudit/analysis/__init__.py` export pattern

## AI Agent Notes
- Focus on medical device security: HL7 protocol analysis, PII in healthcare contexts, proxy testing with security tools
- Preserve heuristic detection approach over complex deep inspection
- Maintain console-based output for security tool usability
- Follow embedded docstring instructions in each module for context-aware extensions
- Proxy enables Burp Suite/ZAP integration for medical device testing