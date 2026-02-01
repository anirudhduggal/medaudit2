# Medaudit HL7 Fuzzer - Configuration Templates
# Default fuzzing configurations for medical device testing

"""
Fuzzing Configuration Templates

This module provides default YAML and JSON templates for fuzzing configuration.
Templates include examples of all supported fuzzing strategies and can be
customized for specific target devices.

Supported Rule Types:
- Field mutations (target: "field")
- Segment manipulations (target: "segment")
- Message-level mutations (target: "message")

Strategies:
- Field: all, overflow, boundary, custom, random, sql, format, cmd, unicode
- Segment: add, remove, reorder
- Message: delimiter
"""

# YAML Configuration Template
DEFAULT_FUZZING_CONFIG_YAML = """
# Medaudit HL7 Medical Device Fuzzer Configuration
# ================================================
# This configuration defines fuzzing rules for testing HL7/MLLP medical devices.

name: "HL7 Fuzzing Job"
target_host: "localhost"
target_port: 2575
use_tls: false
delay_ms: 100
timeout_seconds: 30
stop_on_error: false
max_requests: 1000

# Base HL7 message to fuzz
# Use {timestamp} and {msg_id} as placeholders for auto-generated values
base_message: |
  MSH|^~\\&|FUZZER|TEST|TARGET|DEVICE|{timestamp}||ADT^A01|{msg_id}|P|2.5
  PID|1||12345||DOE^JOHN^^^||19800101|M|||123 Main St^^City^ST^12345||555-0100

# Fuzzing rules
rules:
  # =============================================================================
  # FIELD MUTATION RULES
  # =============================================================================
  
  # Test all mutation types on Patient ID
  - name: "Fuzz Patient ID - All Strategies"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 3
    strategy: "all"  # Try all mutation types
    iterations: 20

  # Buffer overflow testing on Patient Name
  - name: "Fuzz Patient Name - Overflow"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 5
    strategy: "overflow"
    iterations: 10

  # Boundary value testing on Date of Birth
  - name: "Date Boundaries"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 7
    strategy: "boundary"
    iterations: 10

  # SQL Injection testing
  - name: "SQL Injection Test"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 3
    strategy: "custom"
    values:
      - "' OR '1'='1"
      - "1; DROP TABLE patients;--"
      - "1 UNION SELECT * FROM users"
      - "' AND SLEEP(5)--"

  # Format string attacks
  - name: "Format String Test"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 5
    strategy: "format"
    iterations: 5

  # Command injection testing
  - name: "Command Injection Test"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 11  # Address field
    strategy: "cmd"
    iterations: 5

  # =============================================================================
  # SEGMENT MANIPULATION RULES
  # =============================================================================
  
  # Test handling of missing required segments
  - name: "Segment Removal"
    enabled: true
    target: "segment"
    strategy: "remove"
    iterations: 5

  # Test segment ordering assumptions
  - name: "Segment Reordering"
    enabled: true
    target: "segment"
    strategy: "reorder"
    iterations: 5

  # Test handling of unknown/extra segments
  - name: "Segment Injection"
    enabled: true
    target: "segment"
    strategy: "add"
    iterations: 5

  # =============================================================================
  # MESSAGE-LEVEL RULES
  # =============================================================================
  
  # Test delimiter handling
  - name: "Delimiter Mutation"
    enabled: true
    target: "message"
    strategy: "delimiter"
    iterations: 10
"""

# JSON Configuration Template
DEFAULT_FUZZING_CONFIG_JSON = """{
  "name": "HL7 Fuzzing Job",
  "target_host": "localhost",
  "target_port": 2575,
  "use_tls": false,
  "delay_ms": 100,
  "timeout_seconds": 30,
  "stop_on_error": false,
  "max_requests": 1000,
  "base_message": "MSH|^~\\\\&|FUZZER|TEST|TARGET|DEVICE|{timestamp}||ADT^A01|{msg_id}|P|2.5\\rPID|1||12345||DOE^JOHN^^^||19800101|M|||123 Main St^^City^ST^12345||555-0100",
  "rules": [
    {
      "name": "Fuzz Patient ID - All Strategies",
      "enabled": true,
      "target": "field",
      "segment": "PID",
      "field_index": 3,
      "strategy": "all",
      "iterations": 20
    },
    {
      "name": "SQL Injection Test",
      "enabled": true,
      "target": "field",
      "segment": "PID",
      "field_index": 3,
      "strategy": "custom",
      "values": [
        "' OR '1'='1",
        "1; DROP TABLE patients;--",
        "1 UNION SELECT * FROM users",
        "' AND SLEEP(5)--"
      ]
    },
    {
      "name": "Buffer Overflow Test",
      "enabled": true,
      "target": "field",
      "segment": "PID",
      "field_index": 5,
      "strategy": "overflow",
      "iterations": 10
    },
    {
      "name": "Segment Removal",
      "enabled": true,
      "target": "segment",
      "strategy": "remove",
      "iterations": 5
    },
    {
      "name": "Delimiter Mutation",
      "enabled": true,
      "target": "message",
      "strategy": "delimiter",
      "iterations": 10
    }
  ]
}"""

# Compact templates for specific test scenarios
QUICK_SQLI_TEMPLATE = """
name: "Quick SQL Injection Test"
target_host: "{host}"
target_port: {port}
use_tls: false
delay_ms: 50
timeout_seconds: 10
max_requests: 50
base_message: |
  MSH|^~\\&|TEST|SRC|DST|HOSP|{timestamp}||ADT^A01|{msg_id}|P|2.5
  PID|1||{patient_id}||TEST^PATIENT||19800101|M

rules:
  - name: "SQLi Patient ID"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 3
    strategy: "custom"
    values:
      - "' OR '1'='1"
      - "' OR '1'='1'--"
      - "'; DROP TABLE patients;--"
      - "1 UNION SELECT username, password FROM users--"
      - "' AND 1=0 UNION SELECT NULL, table_name FROM information_schema.tables--"
"""

QUICK_OVERFLOW_TEMPLATE = """
name: "Quick Buffer Overflow Test"
target_host: "{host}"
target_port: {port}
use_tls: false
delay_ms: 100
timeout_seconds: 30
max_requests: 20
base_message: |
  MSH|^~\\&|TEST|SRC|DST|HOSP|{timestamp}||ADT^A01|{msg_id}|P|2.5
  PID|1||12345||TEST^PATIENT||19800101|M

rules:
  - name: "Overflow All Fields"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 5
    strategy: "overflow"
    iterations: 20
"""

QUICK_DELIMITER_TEMPLATE = """
name: "Quick Delimiter Fuzzing"
target_host: "{host}"
target_port: {port}
use_tls: false
delay_ms: 100
timeout_seconds: 10
max_requests: 20
base_message: |
  MSH|^~\\&|TEST|SRC|DST|HOSP|{timestamp}||ADT^A01|{msg_id}|P|2.5
  PID|1||12345||TEST^PATIENT||19800101|M

rules:
  - name: "Delimiter Mutations"
    enabled: true
    target: "message"
    strategy: "delimiter"
    iterations: 20
"""


def get_template(template_type: str = "full", format: str = "yaml") -> str:
    """
    Get a fuzzing configuration template.
    
    Args:
        template_type: Type of template:
            - 'full': Complete template with all strategies
            - 'sqli': Quick SQL injection test
            - 'overflow': Quick buffer overflow test
            - 'delimiter': Quick delimiter fuzzing
        format: Output format ('yaml' or 'json')
        
    Returns:
        Template string in requested format
        
    Example:
        >>> yaml_config = get_template("full", "yaml")
        >>> json_config = get_template("sqli", "json")
    """
    templates = {
        "full": {
            "yaml": DEFAULT_FUZZING_CONFIG_YAML,
            "json": DEFAULT_FUZZING_CONFIG_JSON
        },
        "sqli": {
            "yaml": QUICK_SQLI_TEMPLATE,
            "json": None  # Convert from YAML if needed
        },
        "overflow": {
            "yaml": QUICK_OVERFLOW_TEMPLATE,
            "json": None
        },
        "delimiter": {
            "yaml": QUICK_DELIMITER_TEMPLATE,
            "json": None
        }
    }
    
    template = templates.get(template_type, templates["full"])
    result = template.get(format)
    
    if result is None and format == "json":
        # Convert YAML to JSON if JSON not available
        import yaml
        import json
        yaml_template = template.get("yaml", DEFAULT_FUZZING_CONFIG_YAML)
        parsed = yaml.safe_load(yaml_template)
        result = json.dumps(parsed, indent=2)
    
    return result
