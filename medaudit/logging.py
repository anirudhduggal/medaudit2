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

    def log_http_request(self, method: str, path: str, headers: Dict[str, str] = None,
                        body: str = None, client_ip: str = None, content_length: int = 0) -> str:
        """Log an HTTP request."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "http_request",
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "content_length": content_length
        }
        
        if headers:
            log_entry["headers"] = dict(headers)
        if body:
            log_entry["body_preview"] = body[:500] + "..." if len(body) > 500 else body

        return self._write_log_entry(log_entry, "http_requests")

    def log_hl7_conversion(self, http_body: str = None, hl7_message: str = None,
                          original_length: int = 0, hl7_length: int = 0,
                          hl7_message_start: str = None) -> str:
        """Log HL7 message conversion."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "hl7_conversion",
            "original_length": original_length or (len(http_body) if http_body else 0),
            "hl7_length": hl7_length or (len(hl7_message) if hl7_message else 0),
        }
        
        if hl7_message_start:
            log_entry["hl7_message_start"] = hl7_message_start
        elif hl7_message:
            log_entry["hl7_message_preview"] = hl7_message[:300] + "..." if len(hl7_message) > 300 else hl7_message

        return self._write_log_entry(log_entry, "hl7_conversions")

    def log_hl7_response(self, hl7_host: str = None, hl7_port: int = None, response: str = None,
                        success: bool = None, error_message: str = None, status: str = None,
                        response_length: int = 0, hl7_ack: str = None) -> str:
        """Log HL7 server response."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "hl7_response",
            "status": status or ("success" if success else "error"),
            "response_length": response_length or (len(response) if response else 0),
        }
        
        if hl7_host and hl7_port:
            log_entry["hl7_server"] = f"{hl7_host}:{hl7_port}"
        if hl7_ack:
            log_entry["hl7_ack"] = hl7_ack
        elif response:
            log_entry["response_preview"] = response[:300] + "..." if len(response) > 300 else response
        if error_message:
            log_entry["error_message"] = error_message

        return self._write_log_entry(log_entry, "hl7_responses")
    
    def log_error(self, error_message: str, error_type: str = "general", context: Dict[str, Any] = None) -> str:
        """Log a general error."""
        log_entry = {
            "timestamp": self._get_timestamp(),
            "type": "error",
            "error_type": error_type,
            "error_message": error_message,
            "context": context or {}
        }

        return self._write_log_entry(log_entry, "proxy_errors")

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