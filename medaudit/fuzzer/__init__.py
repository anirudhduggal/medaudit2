# Medaudit HL7 Fuzzer Module
# Dedicated fuzzer for medical device security testing

"""
HL7 Medical Device Fuzzer

This module provides comprehensive fuzzing capabilities for HL7/MLLP-based
medical devices. It includes mutation strategies, message generation, and
protocol handling specifically designed for healthcare system security testing.

Components:
- strategies: Mutation strategies for HL7 messages (field, delimiter, segment)
- engine: Fuzzing job execution and result analysis
- protocol: HL7/MLLP communication handling
- templates: Default fuzzing configuration templates (YAML/JSON)
- malicious_hl7_server: Malicious HL7 server for testing client robustness
"""

from .strategies import FuzzingStrategies
from .engine import (
    FuzzingRule,
    FuzzingConfig,
    generate_fuzzed_messages,
    run_fuzzing_job,
    parse_fuzzing_config,
)
from .protocol import send_hl7_message, MLLP_START, MLLP_END
from .templates import (
    DEFAULT_FUZZING_CONFIG_YAML,
    DEFAULT_FUZZING_CONFIG_JSON,
)
from .malicious_hl7_server import (
    MaliciousHL7Server,
    AttackMode,
    AttackConfig,
    quick_test_no_ack,
    quick_test_broken_ack,
    quick_test_flood,
    quick_test_random,
)
from .traffic_logger import FuzzingTrafficLogger, FuzzingTrafficEntry

__all__ = [
    # Strategies
    "FuzzingStrategies",
    # Engine
    "FuzzingRule",
    "FuzzingConfig",
    "generate_fuzzed_messages",
    "run_fuzzing_job",
    "parse_fuzzing_config",
    # Protocol
    "send_hl7_message",
    "MLLP_START",
    "MLLP_END",
    # Templates
    "DEFAULT_FUZZING_CONFIG_YAML",
    "DEFAULT_FUZZING_CONFIG_JSON",
    # Malicious Server
    "MaliciousHL7Server",
    "AttackMode",
    "AttackConfig",
    "quick_test_no_ack",
    "quick_test_broken_ack",
    "quick_test_flood",
    "quick_test_random",
    # Traffic Logging
    "FuzzingTrafficLogger",
    "FuzzingTrafficEntry",
]

__version__ = "1.0.0"
