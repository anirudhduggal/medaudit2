# Medaudit 2.0 - AI Agent Instructions

## Project Overview
Medaudit 2.0 is a comprehensive medical device security auditing tool that analyzes network traffic and provides HTTP-to-HL7 proxy functionality. It processes PCAP files to detect encryption status, extract HL7 v2.x messages, and identify personally identifiable information (PII) in unencrypted traffic. The proxy enables testing medical devices with tools like Burp Suite by converting HTTP requests to HL7 messages.

## Architecture
- **Modular packages**: `medaudit.analysis` (with `traffic`, `pii`, and `dicom` submodules) for analysis, `medaudit.proxy` (asyncio-based) for HTTP-to-HL7 conversion, `medaudit.config` (Pydantic-based) for configuration management, `medaudit.logging` for proxy activity logging
- **Entry point**: `python -m medaudit analyze <pcap_file>` for analysis, `python -m medaudit proxy` for proxy server, `python -m medaudit config` for configuration
- **Data flow**: PCAP → scapy parsing → encryption detection (deterministic) → HL7/DICOM parsing → PII scanning; HTTP → HL7 conversion → MLLP wrapping → target device; All proxy activities logged to date-organized JSON files

## Key Workflows
- **Analysis**: Run `python -m medaudit analyze medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap` for testing
- **Proxy**: Run `python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575` to start HTTP-to-HL7 proxy
- **Remote Proxy**: Use `--hl7-host <remote_ip>` and `--hl7-port <port>` to forward to external medical devices
- **Configuration**: Create `medaudit.json` for default settings, use `python -m medaudit config --create`
- **Testing**: Run tests from `tests/` directory:
  - `pytest tests/test_pii_check.py` - PII detection unit tests
  - `python tests/test_comprehensive.py` - Core component tests
  - `python tests/analyze_pcap_pii.py` - PCAP PII extraction analysis
  - Results saved to `tests/results/`, logs to `tests/logs/`
- **Extension**: Add analysis submodules in `medaudit/analysis/`, PII patterns in `medaudit/analysis/pii/pii_check.py`, proxy features in `medaudit/proxy/`

## Configuration System
- **File locations**: `medaudit.json` (current dir), `~/.medaudit.json`, `~/.config/medaudit.json`
- **Command line override**: CLI arguments take precedence over config file values
- **Default creation**: `python -m medaudit config --create` generates default config
- **Current config**: `python -m medaudit config --show` displays loaded configuration
- **Structure**:
  ```json
  {
    "proxy": {"http_port": 8080, "hl7_host": "localhost", "hl7_port": 2575},
    "analysis": {"max_hl7_messages": 10, "max_pii_instances": 20},
    "logging": {"enabled": true, "log_dir": "logs"}
  }
  ```

## Code Patterns
- **Encryption detection**: Heuristic approach using SSL ports (443, 993, 995, 465, 587) + payload entropy (>0.8 ratio)
- **HL7 identification**: Check for "MSH|" prefix in decoded UTF-8 payload
- **HL7 conversion**: Wrap messages in MLLP format (`\x0b{message}\x1c\r`) for transport
- **PII validation**: Credit cards use Luhn algorithm; regex patterns for names (`[A-Z][a-z]+\s[A-Z][a-z]+`), addresses (`\d+\s+[A-Za-z0-9\s,.-]+`)
- **Error handling**: Decode payloads with `errors='ignore'` to handle binary data gracefully
- **Output limiting**: Show first 10 HL7 messages, 20 PII instances to prevent console overflow
- **Modular imports**: Unified access via `medaudit.analysis`, direct access via `medaudit.analysis.traffic/pii`
- **Logging system**: JSON Lines format (.jsonl files) for structured logging, date-organized folders (logs/YYYY-MM-DD/), comprehensive proxy activity tracking

## PII Detection & Security Analysis
- **MLLP-Wrapped HL7 Detection**: Successfully parses MLLP-wrapped HL7 v2.x messages from PCAP files
- **Unencrypted PII Exposure**: Identifies and extracts unencrypted PII from medical device traffic (patient names, IDs, addresses, phone numbers)
- **HL7 Field Parsing**: Extracts PII from standard HL7 segments (MSH, PID, PV1) using pipe-delimited field structure (e.g., "DOE^JOHN^^^" for names)
- **Test Data**: hl7_v2_unencrypted_synthetic.pcap contains realistic PII to demonstrate security vulnerability
- **Presidio-Based Detection**: Uses Microsoft Presidio Analyzer with Spacy NLP engine for entity recognition
  - Supported Entity Types: PERSON, PHONE_NUMBER, EMAIL_ADDRESS, SSN, CREDIT_CARD, LOCATION, etc.
  - Configuration: Uses `en_core_web_lg` Spacy model for NER (downloaded via `python -m spacy download en_core_web_lg`)
  - HL7 Medical Context: Can be configured with custom recognizers for medical-specific entities (MRN, Provider names, etc.)
  - Fallback Methods: Regex patterns and manual parsing for entities Presidio may miss in medical data formats
  - Performance: NLP-based detection is computationally intensive; results cached when processing large PCAP files

## Dependencies & Integration
- **Core library**: scapy for PCAP parsing (`from scapy.all import rdpcap, TCP, UDP, Raw`)
- **PII Detection**: presidio-analyzer and presidio-anonymizer for entity recognition and redaction
  - Uses `AnalyzerEngine` from `presidio_analyzer` module
  - Requires Spacy NLP engine provider: `NlpEngineProvider` with `en_core_web_lg` model
  - Custom recognizers: `CreditCardRecognizer`, `UsSsnRecognizer` pre-configured
  - Analyzer configuration: See `medaudit/analysis/pii/pii_check.py` for implementation patterns
- **NLP Engine**: Spacy (`python -m spacy download en_core_web_lg`)
  - Model size: ~40MB, provides PERSON, ORG, GPE entity recognition
  - Integration: Loaded via `NlpEngineProvider(nlp_configuration={...})`
- **Input format**: Wireshark PCAP files with Ethernet frames; HTTP POST requests for proxy
- **Output**: Console reports with encryption ratios, HL7 headers, PII classifications (with Presidio entity types); HL7 responses converted back to HTTP; JSON Lines logs for proxy activities
- **Extension points**: Add new analysis submodules following `medaudit/analysis/traffic/` pattern; custom Presidio recognizers in `medaudit/analysis/pii/pii_check.py`

## AI Agent Notes
- Focus on medical device security: HL7 protocol analysis, PII in healthcare contexts, proxy testing with security tools
- Preserve heuristic detection approach over complex deep inspection
- Maintain console-based output for security tool usability
- Follow embedded docstring instructions in each module for context-aware extensions
- Proxy enables Burp Suite/ZAP integration for medical device testing
- Configuration system allows flexible deployment across different environments
- Modular analysis structure supports adding new security checks (vulnerability scanning, compliance validation, etc.)
- MLLP protocol handling for HL7 v2.x transport and security validation
- PII detection optimized for healthcare data formats (pipe-delimited HL7 fields, name components)
- **Presidio Usage**: When extending PII detection, use `AnalyzerEngine.analyze()` for NLP-based detection; combine with regex for hybrid approach
- **Medical Entity Configuration**: Add custom recognizers for domain-specific PII (MRN patterns, medical provider identifiers, facility names)
- **Performance Optimization**: Cache Presidio analyzer instance; Spacy model loads once at startup
- **Integration Testing**: Verify new PII detectors work with test synthetic PCAP files; check entity type mappings in `tests/test_pii_check.py`