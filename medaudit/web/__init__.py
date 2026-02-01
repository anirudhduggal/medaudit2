"""
Medaudit Web UI Module
Provides a comprehensive web interface for medical device security auditing.

Features:
- User authentication and project management
- HL7 Client with malformed payload library
- HL7 Fuzzer with YAML/JSON rule configuration
- PCAP traffic analysis with network flow visualization
- Multi-server management with TLS support
- PDF report export
"""

from .app import app, start_web_server

__all__ = ['app', 'start_web_server']
