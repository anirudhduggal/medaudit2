#!/usr/bin/env python3
"""
Medaudit 2.0 - Main Entry Point
AI Agent Instructions:
- This is the main entry point for the Medaudit 2.0 application
python -m medaudit web --host 0.0.0.0 --port 8080- Run with: python -m medaudit analyze <pcap_file> for traffic analysis
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
    web_parser.add_argument('--password', type=str, default=None,
                           help='Set custom admin password')
    web_parser.add_argument('--generate-password', action='store_true',
                           help='Generate a random secure password for admin')

    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('--create', action='store_true', help='Create default configuration file')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')

    # User management command
    user_parser = subparsers.add_parser('user', help='User management (localhost only)')
    user_parser.add_argument('--create', action='store_true', help='Create a new user')
    user_parser.add_argument('--username', type=str, help='Username for the new user')
    user_parser.add_argument('--password', type=str, help='Password for the new user')
    user_parser.add_argument('--full-name', type=str, help='Full name (optional)')
    user_parser.add_argument('--admin', action='store_true', help='Make user an admin')

    args = parser.parse_args()

    if args.command == 'analyze':
        analyze_pcap(args.pcap_file)
    elif args.command == 'proxy':
        start_proxy(http_port=args.port, hl7_host=args.hl7_host, hl7_port=args.hl7_port)
    elif args.command == 'web':
        from .web import start_web_server
        start_web_server(
            host=args.host, 
            port=args.port,
            admin_password=args.password,
            generate_password=args.generate_password
        )
    elif args.command == 'config':
        if args.create:
            config.create_default_config()
        elif args.show:
            print("Current configuration:")
            print(json.dumps(config.config, indent=2))
        else:
            print("Use --create to generate default config or --show to display current config")
    elif args.command == 'user':
        if args.create:
            if not args.username or not args.password:
                print("Error: --username and --password are required")
                sys.exit(1)
            
            import requests
            url = "http://127.0.0.1:8080/auth/create-user"
            
            try:
                response = requests.post(url, json={
                    "username": args.username,
                    "password": args.password,
                    "full_name": args.full_name,
                    "is_admin": args.admin
                })
                
                if response.ok:
                    data = response.json()
                    print(f"✓ User '{args.username}' created successfully")
                    if args.admin:
                        print(f"  Role: Administrator")
                    else:
                        print(f"  Role: Regular user")
                else:
                    error = response.json().get('detail', 'Unknown error')
                    print(f"✗ Failed to create user: {error}")
                    sys.exit(1)
            except requests.exceptions.ConnectionError:
                print("✗ Error: Cannot connect to server at http://127.0.0.1:8080")
                print("  Make sure the web server is running: python -m medaudit web")
                sys.exit(1)
        else:
            print("Use --create with --username and --password to create a user")
            print("Example: python -m medaudit user --create --username john --password pass123 --full-name 'John Doe'")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()