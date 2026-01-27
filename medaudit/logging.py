"""
Logging Module for Medaudit 2.0
AI Agent Instructions:
- This module handles logging of HTTP requests and HL7 responses
- Creates date-organized folder structure for logs
- Logs are saved as JSON for easy parsing and analysis
- Use log_http_request() and log_hl7_response() functions
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

class ProxyLogger:
    """Logger for HTTP-to-HL7 proxy activities."""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

    def _get_date_folder(self) -> Path:
        """Get the folder for today's date."""
        today = datetime.now().strftime("%Y-%m-%d")
        date_folder = self.log_dir / today
        date_folder.mkdir(exist_ok=True)
        return date_folder

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now().isoformat()

    def log_http_request(self, method: str, path: str, headers: Dict[str, str],
                        body: str, client_ip: str) -> str:
        """Log an HTTP request."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "http_request",
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "headers": dict(headers),
            "body_length": len(body),
            "body_preview": body[:500] + "..." if len(body) > 500 else body
        }

        return self._write_log_entry(log_entry, "http_requests")

    def log_hl7_conversion(self, http_body: str, hl7_message: str) -> str:
        """Log HL7 message conversion."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "hl7_conversion",
            "http_body_length": len(http_body),
            "http_body_preview": http_body[:200] + "..." if len(http_body) > 200 else http_body,
            "hl7_message_length": len(hl7_message),
            "hl7_message_preview": hl7_message[:300] + "..." if len(hl7_message) > 300 else hl7_message
        }

        return self._write_log_entry(log_entry, "hl7_conversions")

    def log_hl7_response(self, hl7_host: str, hl7_port: int, response: str,
                        success: bool, error_message: str = None) -> str:
        """Log HL7 server response."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "hl7_response",
            "hl7_server": f"{hl7_host}:{hl7_port}",
            "success": success,
            "response_length": len(response) if response else 0,
            "response_preview": response[:300] + "..." if response and len(response) > 300 else response,
            "error_message": error_message
        }

        return self._write_log_entry(log_entry, "hl7_responses")

    def log_proxy_error(self, error_type: str, error_message: str, context: Dict[str, Any] = None) -> str:
        """Log proxy errors."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "proxy_error",
            "error_type": error_type,
            "error_message": error_message,
            "context": context or {}
        }

        return self._write_log_entry(log_entry, "proxy_errors")

    def _write_log_entry(self, log_entry: Dict[str, Any], log_type: str) -> str:
        """Write a log entry to file."""
        date_folder = self._get_date_folder()
        log_file = date_folder / f"{log_type}.jsonl"

        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')

            return str(log_file)
        except Exception as e:
            print(f"Warning: Failed to write log entry: {e}")
            return ""

    def get_log_files_today(self) -> Dict[str, Path]:
        """Get all log files for today."""
        date_folder = self._get_date_folder()
        log_files = {}

        for log_file in date_folder.glob("*.jsonl"):
            log_type = log_file.stem
            log_files[log_type] = log_file

        return log_files

# Global logger instance - will be initialized with config
logger = None

def init_logger(config):
    """Initialize the global logger with configuration."""
    global logger
    if logger is None:
        logging_config = config.get_logging_config()
        if logging_config.get("enabled", True):
            logger = ProxyLogger(logging_config.get("log_dir", "logs"))
        else:
            logger = None
    return logger