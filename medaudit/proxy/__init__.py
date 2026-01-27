"""
Proxy Package for Medaudit 2.0
AI Agent Instructions:
- This package contains HTTP-to-HL7 proxy functionality
- Import start_proxy from proxy_server module
- Used for converting HTTP requests to HL7 messages for medical device testing
"""

from .proxy_server import start_proxy

__all__ = ['start_proxy']