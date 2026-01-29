"""
CLI Interface for HL7 Server

Usage:
    python -m hl7server.cli start [--host HOST] [--port PORT] [--use-tls]
    python -m hl7server.cli config --create [--path PATH]
    python -m hl7server.cli config --show
"""

import argparse
import sys
from pathlib import Path
import time

from .hl7_mock_server import HL7Server
from .server_config import ServerConfig


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="HL7 2.x Mock Server for Medaudit 2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Start non-encrypted server:
    python -m hl7server start

  Start with custom host/port:
    python -m hl7server start --host 0.0.0.0 --port 3000

  Start with TLS encryption:
    python -m hl7server start --use-tls --cert-file server.crt --key-file server.key

  Create default configuration:
    python -m hl7server config --create

  Show current configuration:
    python -m hl7server config --show
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Start server command
    start_parser = subparsers.add_parser('start', help='Start HL7 server')
    start_parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    start_parser.add_argument('--port', type=int, default=2575, help='Server port (default: 2575)')
    start_parser.add_argument('--use-tls', action='store_true', help='Enable TLS/SSL encryption')
    start_parser.add_argument('--cert-file', help='Path to SSL certificate file')
    start_parser.add_argument('--key-file', help='Path to SSL key file')
    start_parser.add_argument('--config', help='Path to configuration file')
    start_parser.add_argument('--log-dir', default='logs/hl7server', help='Logging directory')

    # Config command
    config_parser = subparsers.add_parser('config', help='Manage server configuration')
    config_group = config_parser.add_mutually_exclusive_group()
    config_group.add_argument('--create', action='store_true', help='Create default configuration')
    config_group.add_argument('--show', action='store_true', help='Show current configuration')
    config_parser.add_argument('--path', help='Path to configuration file')

    args = parser.parse_args()

    if args.command == 'start':
        start_server(args)
    elif args.command == 'config':
        handle_config(args)
    else:
        parser.print_help()
        sys.exit(1)


def start_server(args):
    """Start the HL7 server."""
    try:
        # Load configuration if provided
        config = None
        if args.config:
            config = ServerConfig(args.config)
            server_config = config.get_server_config()
            host = args.host if args.host != 'localhost' else server_config.get('host', 'localhost')
            port = args.port if args.port != 2575 else server_config.get('port', 2575)
            use_tls = args.use_tls or server_config.get('use_tls', False)
        else:
            host = args.host
            port = args.port
            use_tls = args.use_tls

        # Validate TLS settings
        if use_tls and not (args.cert_file and args.key_file):
            print("Error: --cert-file and --key-file required when using --use-tls")
            sys.exit(1)

        cert_file = args.cert_file
        key_file = args.key_file
        log_dir = args.log_dir

        # Create and start server
        server = HL7Server(
            host=host,
            port=port,
            use_tls=use_tls,
            cert_file=cert_file,
            key_file=key_file,
            log_dir=log_dir,
            verbose=True
        )

        server.start()

        print("\n" + "="*60)
        print("HL7 2.x Mock Server Running")
        print("="*60)
        print(f"Host:      {host}")
        print(f"Port:      {port}")
        print(f"Encrypted: {'Yes (TLS/SSL)' if use_tls else 'No (Plain TCP)'}")
        print(f"Log Dir:   {log_dir}")
        print("\nPress Ctrl+C to stop the server...")
        print("="*60 + "\n")

        # Keep server running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nShutting down server...")
            server.stop()
            print("Server stopped.")

    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)


def handle_config(args):
    """Handle configuration commands."""
    try:
        config = ServerConfig(args.path)

        if args.create:
            path = config.create_default_config(args.path)
            print(f"✓ Configuration file created at: {path}")

        elif args.show:
            config.show_config()

        else:
            print("Use --create to create config or --show to display config")

    except Exception as e:
        print(f"Error handling configuration: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
