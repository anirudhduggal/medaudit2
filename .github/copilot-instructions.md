# Medaudit 2.0 - AI Agent Instructions

## Project Overview
Medaudit 2.0 analyzes medical device network traffic for security auditing. It processes PCAP files to detect encryption status, extract HL7 v2.x messages, and identify personally identifiable information (PII) in unencrypted traffic.

## Architecture
- **Modular packages**: `medaudit.analysis` for traffic parsing, `medaudit.pii` for sensitive data detection
- **Entry point**: `python -m medaudit <pcap_file>` calls `analyze_pcap()` from `medaudit/analysis/traffic_analysis.py`
- **Data flow**: PCAP → scapy parsing → encryption heuristics → HL7 detection ("MSH|" prefix) → PII scanning

## Key Workflows
- **Analysis**: Run `python -m medaudit medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap` for testing
- **Extension**: Add analysis features in `medaudit/analysis/`, PII patterns in `medaudit/pii/pii_check.py`
- **Testing**: Use synthetic PCAP files in `medaudit/testFiles/` for development validation

## Code Patterns
- **Encryption detection**: Heuristic approach using SSL ports (443, 993, 995, 465, 587) + payload entropy (>0.8 ratio)
- **HL7 identification**: Check for "MSH|" prefix in decoded UTF-8 payload
- **PII validation**: Credit cards use Luhn algorithm; regex patterns for names (`[A-Z][a-z]+\s[A-Z][a-z]+`), addresses (`\d+\s+[A-Za-z0-9\s,.-]+`)
- **Error handling**: Decode payloads with `errors='ignore'` to handle binary data gracefully
- **Output limiting**: Show first 10 HL7 messages, 20 PII instances to prevent console overflow

## Dependencies & Integration
- **Core library**: scapy for PCAP parsing (`from scapy.all import rdpcap, TCP, UDP, Raw`)
- **Input format**: Wireshark PCAP files with Ethernet frames
- **Output**: Console reports with encryption ratios, HL7 headers, PII classifications
- **Extension points**: Modular design allows adding new detection modules following `medaudit/analysis/__init__.py` export pattern

## AI Agent Notes
- Focus on medical device security: HL7 protocol analysis, PII in healthcare contexts
- Preserve heuristic detection approach over complex deep inspection
- Maintain console-based output for security tool usability
- Follow embedded docstring instructions in each module for context-aware extensions