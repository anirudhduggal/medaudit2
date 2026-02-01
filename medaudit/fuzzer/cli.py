# Medaudit HL7 Fuzzer - CLI Interface
# Command-line interface for standalone fuzzing

"""
HL7 Fuzzer CLI

Provides command-line access to the fuzzer for standalone operation
without the web UI. Supports loading configs from files, quick tests,
and output in various formats.

Usage:
    python -m medaudit.fuzzer run -c config.yaml -o results.json
    python -m medaudit.fuzzer test --host localhost --port 2575
    python -m medaudit.fuzzer template --format yaml > my_config.yaml
"""

import argparse
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from .engine import (
    parse_fuzzing_config,
    validate_config,
    run_fuzzing_job,
    generate_fuzzed_messages,
)
from .protocol import test_connection, send_hl7_message
from .templates import DEFAULT_FUZZING_CONFIG_YAML, DEFAULT_FUZZING_CONFIG_JSON, get_template

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    """Configure logging for CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def cmd_run(args):
    """Execute a fuzzing job from config file."""
    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        return 1
    
    content = config_path.read_text()
    config_format = "yaml" if config_path.suffix in [".yaml", ".yml"] else "json"
    
    try:
        config = parse_fuzzing_config(content, config_format)
    except ValueError as e:
        print(f"Error parsing config: {e}", file=sys.stderr)
        return 1
    
    # Validate
    valid, errors = validate_config(config)
    if not valid:
        print("Configuration errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    
    # Override config with CLI args
    if args.host:
        config["target_host"] = args.host
    if args.port:
        config["target_port"] = args.port
    if args.max_requests:
        config["max_requests"] = args.max_requests
    
    # Generate job ID
    job_id = f"cli-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    print(f"Starting fuzzing job: {config.get('name', job_id)}")
    print(f"Target: {config['target_host']}:{config.get('target_port', 2575)}")
    print(f"Rules: {len(config.get('rules', []))}")
    print("-" * 50)
    
    # Progress callback
    last_progress = 0
    def progress_callback(progress, stats):
        nonlocal last_progress
        if progress >= last_progress + 10:
            last_progress = progress
            print(f"Progress: {progress}% | Requests: {stats['total_requests']} | "
                  f"Interesting: {stats['interesting']}")
    
    # Run fuzzing
    result = run_fuzzing_job(job_id, config, progress_callback=progress_callback)
    
    print("-" * 50)
    print(f"Status: {result['status']}")
    print(f"Total Requests: {result['total_requests']}")
    print(f"Successful: {result.get('successful', 0)}")
    print(f"Errors: {result.get('errors', 0)}")
    print(f"Interesting Findings: {result.get('interesting', 0)}")
    
    # Save results if output specified
    if args.output:
        output_path = Path(args.output)
        result["timestamp"] = datetime.now().isoformat()
        result["config"] = config
        
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\nResults saved to: {output_path}")
    
    # Print findings summary
    findings = result.get("findings", [])
    if findings:
        print(f"\n{'='*50}")
        print("INTERESTING FINDINGS:")
        print("="*50)
        for i, finding in enumerate(findings[:20], 1):
            print(f"\n[{i}] {finding['rule']} - {finding['finding_type']}")
            print(f"    Mutation: {finding['mutation']}")
            if finding.get('error'):
                print(f"    Error: {finding['error']}")
            if finding.get('response_time_ms'):
                print(f"    Response Time: {finding['response_time_ms']}ms")
        
        if len(findings) > 20:
            print(f"\n... and {len(findings) - 20} more findings (see output file)")
    
    return 0 if result['status'] == 'completed' else 1


def cmd_test(args):
    """Test connectivity to an HL7 server."""
    print(f"Testing connection to {args.host}:{args.port}...")
    
    result = test_connection(args.host, args.port, args.tls, timeout=5)
    
    if result["connected"]:
        print(f"✓ Connected successfully (latency: {result['latency_ms']}ms)")
        
        # Send test message if requested
        if args.send_test:
            print("\nSending test HL7 message...")
            test_msg = (
                "MSH|^~\\&|TEST|CLI|TARGET|DEVICE|{timestamp}||ADT^A01|{msg_id}|P|2.5\r"
                "PID|1||TEST123||CLI^TEST||19800101|M"
            )
            
            response = send_hl7_message(args.host, args.port, test_msg, args.tls)
            
            if response["success"]:
                print(f"✓ Received response ({response['response_time_ms']}ms)")
                print(f"  Response: {response['response'][:200]}")
            else:
                print(f"✗ Error: {response.get('error', 'unknown')}")
        
        return 0
    else:
        print(f"✗ Connection failed: {result.get('error', 'unknown')}")
        return 1


def cmd_template(args):
    """Output a fuzzing config template."""
    template = get_template(args.type, args.format)
    print(template)
    return 0


def cmd_validate(args):
    """Validate a fuzzing configuration file."""
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        return 1
    
    content = config_path.read_text()
    config_format = "yaml" if config_path.suffix in [".yaml", ".yml"] else "json"
    
    try:
        config = parse_fuzzing_config(content, config_format)
    except ValueError as e:
        print(f"✗ Parse error: {e}", file=sys.stderr)
        return 1
    
    valid, errors = validate_config(config)
    
    if valid:
        print("✓ Configuration is valid")
        print(f"  Name: {config.get('name', 'unnamed')}")
        print(f"  Target: {config.get('target_host')}:{config.get('target_port', 2575)}")
        print(f"  Rules: {len(config.get('rules', []))}")
        return 0
    else:
        print("✗ Configuration errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1


def cmd_list_messages(args):
    """List messages that would be generated from a config."""
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        return 1
    
    content = config_path.read_text()
    config_format = "yaml" if config_path.suffix in [".yaml", ".yml"] else "json"
    
    try:
        config = parse_fuzzing_config(content, config_format)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    base_message = config.get("base_message", "")
    rules = config.get("rules", [])
    
    count = 0
    max_show = args.limit or 50
    
    for msg_data in generate_fuzzed_messages(base_message, rules):
        count += 1
        if count <= max_show:
            print(f"\n[{count}] Rule: {msg_data['rule']}")
            print(f"    Mutation: {msg_data['mutation']}")
            if args.verbose:
                print(f"    Message: {msg_data['message'][:200]}...")
    
    print(f"\nTotal messages: {count}")
    if count > max_show:
        print(f"(showing first {max_show}, use --limit to see more)")
    
    return 0


def cmd_malicious_server(args):
    """Start the malicious HL7 server."""
    from .malicious_hl7_server import MaliciousHL7Server, AttackMode
    
    # Map attack mode string to enum
    mode_map = {
        "normal": AttackMode.NORMAL,
        "no_ack": AttackMode.NO_ACK,
        "delayed_ack": AttackMode.DELAYED_ACK,
        "broken_ack": AttackMode.BROKEN_ACK,
        "flood_ack": AttackMode.FLOOD_ACK,
        "partial_ack": AttackMode.PARTIAL_ACK,
        "wrong_mllp": AttackMode.WRONG_MLLP,
        "overflow_ack": AttackMode.OVERFLOW_ACK,
        "injection_ack": AttackMode.INJECTION_ACK,
        "slow_drip": AttackMode.SLOW_DRIP,
        "connection_drop": AttackMode.CONNECTION_DROP,
        "reset_connection": AttackMode.RESET_CONNECTION,
        "random_data": AttackMode.RANDOM_DATA,
        "replay_request": AttackMode.REPLAY_REQUEST,
        "encoding_attack": AttackMode.ENCODING_ATTACK,
        "nak_flood": AttackMode.NEGATIVE_ACK_FLOOD,
        "random": None,  # Special case for random mode
    }
    
    print("=" * 60)
    print("  MEDAUDIT MALICIOUS HL7 SERVER")
    print("  Medical Device Robustness Testing")
    print("=" * 60)
    
    server = MaliciousHL7Server(
        host=args.host,
        port=args.port,
        use_tls=args.tls,
        cert_file=args.cert,
        key_file=args.key
    )
    
    # Set attack mode
    if args.mode == "random":
        server.config.randomize = True
        print(f"\nAttack Mode: RANDOM (will vary per connection)")
    else:
        mode = mode_map.get(args.mode, AttackMode.NO_ACK)
        server.set_attack_mode(
            mode,
            delay_seconds=args.delay or 0,
            flood_count=args.flood_count or 100,
            overflow_size=args.overflow_size or 1_000_000
        )
        print(f"\nAttack Mode: {mode.value}")
    
    print(f"Listening on: {args.host}:{args.port}")
    print(f"TLS: {'enabled' if args.tls else 'disabled'}")
    print("\nAvailable attack modes:")
    for name in mode_map.keys():
        print(f"  - {name}")
    
    print("\n" + "-" * 60)
    print("Server running. Press Ctrl+C to stop.")
    print("Waiting for connections...\n")
    
    server.start()
    
    try:
        while True:
            time.sleep(1)
            # Print recent logs
            logs = server.get_logs()
            if logs and len(logs) > 0:
                latest = logs[-1]
                if latest.get("timestamp"):
                    print(f"[{latest['timestamp']}] {latest['client']} - "
                          f"{latest['attack_mode']} - "
                          f"Response: {latest['response_sent']}")
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    finally:
        server.stop()
        
        # Print summary
        logs = server.get_logs()
        print(f"\n{'=' * 60}")
        print(f"SESSION SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total connections: {len(logs)}")
        
        if logs:
            # Count by attack mode
            mode_counts = {}
            for log in logs:
                mode = log.get("attack_mode", "unknown")
                mode_counts[mode] = mode_counts.get(mode, 0) + 1
            
            print("\nConnections by attack mode:")
            for mode, count in mode_counts.items():
                print(f"  {mode}: {count}")
        
        # Save logs if output specified
        if args.output:
            output_path = Path(args.output)
            with open(output_path, "w") as f:
                json.dump({
                    "server": {
                        "host": args.host,
                        "port": args.port,
                        "mode": args.mode
                    },
                    "connections": logs
                }, f, indent=2)
            print(f"\nLogs saved to: {output_path}")
    
    return 0


def cmd_list_attacks(args):
    """List available attack modes with descriptions."""
    attacks = {
        "normal": "Send normal ACK response (baseline for comparison)",
        "no_ack": "Don't send any ACK - tests client timeout handling",
        "delayed_ack": "Send ACK after configurable delay - tests timeout thresholds",
        "broken_ack": "Send malformed ACK messages - tests parser robustness",
        "flood_ack": "Send flood of multiple ACKs - tests buffer handling",
        "partial_ack": "Send incomplete ACK without MLLP end - tests stream handling",
        "wrong_mllp": "Use incorrect MLLP framing - tests protocol validation",
        "overflow_ack": "Send huge ACK payload - tests buffer overflow vulnerabilities",
        "injection_ack": "Include SQL/XSS/command injection in ACK - tests input sanitization",
        "slow_drip": "Send response byte-by-byte - tests streaming/timeout handling",
        "connection_drop": "Drop connection mid-response - tests error recovery",
        "reset_connection": "Send TCP RST - tests connection reset handling",
        "random_data": "Send random binary data - tests input validation",
        "replay_request": "Echo request back as response - tests reflection handling",
        "encoding_attack": "Send invalid UTF-8/encoding - tests encoding handling",
        "nak_flood": "Flood with negative ACKs - tests error handling under load",
        "random": "Randomly select attack mode for each connection",
    }
    
    print("=" * 70)
    print("  MALICIOUS HL7 SERVER - AVAILABLE ATTACK MODES")
    print("=" * 70)
    
    for name, desc in attacks.items():
        print(f"\n  {name}")
        print(f"    {desc}")
    
    print("\n" + "=" * 70)
    print("\nUsage examples:")
    print("  python -m medaudit.fuzzer server --mode no_ack --port 2575")
    print("  python -m medaudit.fuzzer server --mode flood_ack --flood-count 500")
    print("  python -m medaudit.fuzzer server --mode delayed_ack --delay 30")
    print("  python -m medaudit.fuzzer server --mode random")
    
    return 0


# Need time import for server command
import time


def main(argv=None):
    """Main entry point for fuzzer CLI."""
    parser = argparse.ArgumentParser(
        description="Medaudit HL7 Medical Device Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run fuzzing from config file
  python -m medaudit.fuzzer run -c config.yaml -o results.json
  
  # Test connection to HL7 server
  python -m medaudit.fuzzer test --host localhost --port 2575
  
  # Generate a config template
  python -m medaudit.fuzzer template --format yaml > my_config.yaml
  
  # Validate a config file
  python -m medaudit.fuzzer validate -c config.yaml
  
  # Start malicious server (no ACK mode)
  python -m medaudit.fuzzer server --mode no_ack --port 2575
  
  # Start malicious server with random attacks
  python -m medaudit.fuzzer server --mode random --port 2575
  
  # List available attack modes
  python -m medaudit.fuzzer attacks
"""
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run fuzzing job")
    run_parser.add_argument("-c", "--config", required=True, help="Config file (YAML/JSON)")
    run_parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    run_parser.add_argument("--host", help="Override target host")
    run_parser.add_argument("--port", type=int, help="Override target port")
    run_parser.add_argument("--max-requests", type=int, help="Override max requests")
    run_parser.set_defaults(func=cmd_run)
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Test HL7 server connection")
    test_parser.add_argument("--host", required=True, help="Target host")
    test_parser.add_argument("--port", type=int, default=2575, help="Target port")
    test_parser.add_argument("--tls", action="store_true", help="Use TLS")
    test_parser.add_argument("--send-test", action="store_true", help="Send test message")
    test_parser.set_defaults(func=cmd_test)
    
    # Template command
    template_parser = subparsers.add_parser("template", help="Output config template")
    template_parser.add_argument("--format", choices=["yaml", "json"], default="yaml",
                                 help="Output format")
    template_parser.add_argument("--type", choices=["full", "sqli", "overflow", "delimiter"],
                                 default="full", help="Template type")
    template_parser.set_defaults(func=cmd_template)
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate config file")
    validate_parser.add_argument("-c", "--config", required=True, help="Config file")
    validate_parser.set_defaults(func=cmd_validate)
    
    # List messages command
    list_parser = subparsers.add_parser("list", help="List generated messages")
    list_parser.add_argument("-c", "--config", required=True, help="Config file")
    list_parser.add_argument("--limit", type=int, help="Max messages to show")
    list_parser.set_defaults(func=cmd_list_messages)
    
    # Malicious server command
    server_parser = subparsers.add_parser("server", help="Start malicious HL7 server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    server_parser.add_argument("--port", type=int, default=2575, help="Listen port")
    server_parser.add_argument("--mode", default="no_ack",
                               choices=["normal", "no_ack", "delayed_ack", "broken_ack",
                                       "flood_ack", "partial_ack", "wrong_mllp",
                                       "overflow_ack", "injection_ack", "slow_drip",
                                       "connection_drop", "reset_connection", "random_data",
                                       "replay_request", "encoding_attack", "nak_flood", "random"],
                               help="Attack mode")
    server_parser.add_argument("--delay", type=float, help="Delay in seconds (for delayed_ack)")
    server_parser.add_argument("--flood-count", type=int, help="Number of messages (for flood modes)")
    server_parser.add_argument("--overflow-size", type=int, help="Payload size (for overflow_ack)")
    server_parser.add_argument("--tls", action="store_true", help="Enable TLS")
    server_parser.add_argument("--cert", help="TLS certificate file")
    server_parser.add_argument("--key", help="TLS private key file")
    server_parser.add_argument("-o", "--output", help="Save connection logs to file")
    server_parser.set_defaults(func=cmd_malicious_server)
    
    # List attacks command
    attacks_parser = subparsers.add_parser("attacks", help="List available attack modes")
    attacks_parser.set_defaults(func=cmd_list_attacks)
    
    args = parser.parse_args(argv)
    
    setup_logging(args.verbose)
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
