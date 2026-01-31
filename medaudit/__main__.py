#!/usr/bin/env python3
"""
Medaudit 2.0 - Main Entry Point
AI Agent Instructions:
- This is the main entry point for the Medaudit 2.0 application
- Run with: python -m medaudit analyze <pcap_file> for traffic analysis
- Run with: python -m medaudit proxy [--port PORT] [--hl7-host HOST] [--hl7-port PORT] for HTTP-to-HL7 proxy
- Run with: python -m medaudit web [--port PORT] [--host HOST] for web UI
- It imports and calls the appropriate functionality
- Configuration loaded from medaudit.json if present
"""

import sys
import argparse
import json
from .analysis import analyze_pcap
from .proxy import start_proxy
from .config import config

def main():
    parser = argparse.ArgumentParser(description='Medaudit 2.0 - Medical Device Security Tool')

    # Global options
    parser.add_argument('--config', help='Path to configuration file (default: medaudit.json)')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze PCAP file for encryption and PII')
    analyze_parser.add_argument('pcap_file', help='Path to PCAP file to analyze')

    # Proxy command
    proxy_parser = subparsers.add_parser('proxy', help='Start HTTP-to-HL7 proxy server')
    proxy_config = config.get_proxy_config()
    proxy_parser.add_argument('--port', type=int, default=proxy_config.get('http_port', 8080),
                             help=f'HTTP port to listen on (default: {proxy_config.get("http_port", 8080)})')
    proxy_parser.add_argument('--hl7-host', default=proxy_config.get('hl7_host', 'localhost'),
                             help=f'HL7 server host (default: {proxy_config.get("hl7_host", "localhost")})')
    proxy_parser.add_argument('--hl7-port', type=int, default=proxy_config.get('hl7_port', 2575),
                             help=f'HL7 server port (default: {proxy_config.get("hl7_port", 2575)})')

    # Web UI command
    web_parser = subparsers.add_parser('web', help='Start the web UI for PCAP analysis')
    web_parser.add_argument('--host', default='0.0.0.0',
                           help='Host to bind the web server (default: 0.0.0.0)')
    web_parser.add_argument('--port', type=int, default=8080,
                           help='Port for the web server (default: 8080)')

    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('--create', action='store_true', help='Create default configuration file')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')

    args = parser.parse_args()

    if args.command == 'analyze':
        analyze_pcap(args.pcap_file)
    elif args.command == 'proxy':
        start_proxy(http_port=args.port, hl7_host=args.hl7_host, hl7_port=args.hl7_port)
    elif args.command == 'web':
        from .web import start_web_server
        start_web_server(host=args.host, port=args.port)
    elif args.command == 'config':
        if args.create:
            config.create_default_config()
        elif args.show:
            print("Current configuration:")
            print(json.dumps(config.config, indent=2))
        else:
            print("Use --create to generate default config or --show to display current config")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()