"""
Logging utilities for Medaudit 2.0

Provides JSON-based logging for various components:
- ProxyLogger: HTTP-to-HL7 proxy activity logging
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from medaudit.paths import LOGS_DIR


class BaseJsonLogger:
    """Base class for JSON-based logging."""

    def __init__(self, log_file: str):
        """Initialize logger with specified log file."""
        self.log_dir = LOGS_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / log_file
        
        # Setup Python logging
        self.logger = logging.getLogger(log_file)
        self.logger.setLevel(logging.INFO)
        
        # File handler for JSON output
        handler = logging.FileHandler(self.log_file)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def _log_json(self, event_type: str, data: dict):
        """Log event as JSON line."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            **data
        }
        self.logger.info(json.dumps(event))


class ProxyLogger(BaseJsonLogger):
    """Logger for HTTP-to-HL7 proxy activity."""

    def __init__(self, log_dir: str = None):
        """Initialize proxy logger."""
        # Use provided directory or default
        if log_dir:
            self.log_dir = Path(log_dir)
            self.log_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.log_dir = LOGS_DIR
            self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logger to file in log_dir
        log_file = self.log_dir / "proxy_activity.jsonl"
        
        self.logger = logging.getLogger("proxy")
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler for JSON output
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def log_http_request(self, method: str, path: str, content_length: int, client_ip: str):
        """Log incoming HTTP request."""
        self._log_json("http_request", {
            "method": method,
            "path": path,
            "content_length": content_length,
            "client_ip": client_ip
        })

    def log_hl7_conversion(self, original_length: int, hl7_length: int, hl7_message_start: str):
        """Log HTTP to HL7 conversion."""
        self._log_json("hl7_conversion", {
            "original_length": original_length,
            "hl7_length": hl7_length,
            "hl7_message_preview": hl7_message_start
        })

    def log_hl7_response(self, status: str, response_length: int, hl7_ack: bytes):
        """Log HL7 server response."""
        self._log_json("hl7_response", {
            "status": status,
            "response_length": response_length,
            "ack_preview": hl7_ack.decode('utf-8', errors='ignore')[:100] if isinstance(hl7_ack, bytes) else str(hl7_ack)[:100]
        })

    def log_error(self, message: str):
        """Log error event."""
        self._log_json("error", {"message": message})

    def _log_json(self, event_type: str, data: dict):
        """Log event as JSON line."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            **data
        }
        self.logger.info(json.dumps(event))
