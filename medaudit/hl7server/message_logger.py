"""
Enhanced Message Logging for HL7 Server

Provides comprehensive logging for all HL7 messages:
- Structured JSON Lines format for analysis
- Time-organized directories (YYYY-MM-DD)
- Message content, metadata, and statistics
- Performance tracking
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import threading


class MessageLogger:
    """Comprehensive message logging for HL7 Server."""

    def __init__(self, log_base_dir: str = "logs/hl7server"):
        """
        Initialize message logger.

        Args:
            log_base_dir: Base directory for all logs
        """
        self.log_base_dir = Path(log_base_dir)
        self.log_base_dir.mkdir(parents=True, exist_ok=True)
        
        # Thread lock for concurrent writes
        self.write_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "messages_received": 0,
            "messages_sent": 0,
            "errors": 0,
            "bytes_received": 0,
            "bytes_sent": 0
        }

    def _get_date_log_dir(self) -> Path:
        """Get date-organized log directory (YYYY-MM-DD)."""
        date_dir = self.log_base_dir / datetime.now().strftime("%Y-%m-%d")
        date_dir.mkdir(parents=True, exist_ok=True)
        return date_dir

    def log_received_message(
        self,
        message: str,
        client_id: int,
        client_address: tuple,
        message_control_id: Optional[str] = None,
        message_type: Optional[str] = None
    ) -> None:
        """
        Log received HL7 message.

        Args:
            message: HL7 message content
            client_id: Client identifier
            client_address: Client IP and port tuple
            message_control_id: HL7 message control ID (from MSH)
            message_type: HL7 message type (e.g., ADT^A01)
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "MESSAGE_RECEIVED",
            "client_id": client_id,
            "client_ip": client_address[0],
            "client_port": client_address[1],
            "message_length": len(message),
            "message_control_id": message_control_id,
            "message_type": message_type,
            "message_preview": message[:200],
            "full_message": message if len(message) <= 1000 else message[:1000] + "...[truncated]"
        }

        with self.write_lock:
            self.stats["messages_received"] += 1
            self.stats["bytes_received"] += len(message)
            self._write_to_jsonl("received_messages.jsonl", log_entry)

    def log_sent_message(
        self,
        message: str,
        client_id: int,
        message_type: str = "ACK"
    ) -> None:
        """
        Log sent HL7 message (typically ACK).

        Args:
            message: HL7 message content
            client_id: Client identifier
            message_type: Type of message being sent
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "MESSAGE_SENT",
            "client_id": client_id,
            "message_type": message_type,
            "message_length": len(message),
            "message_preview": message[:200],
            "full_message": message if len(message) <= 1000 else message[:1000] + "...[truncated]"
        }

        with self.write_lock:
            self.stats["messages_sent"] += 1
            self.stats["bytes_sent"] += len(message)
            self._write_to_jsonl("sent_messages.jsonl", log_entry)

    def log_parsed_hl7(
        self,
        message: str,
        client_id: int,
        parsed_data: Dict[str, Any]
    ) -> None:
        """
        Log parsed HL7 message data.

        Args:
            message: Original HL7 message
            client_id: Client identifier
            parsed_data: Dictionary of parsed HL7 fields
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "HL7_PARSED",
            "client_id": client_id,
            "parsed_data": parsed_data,
            "message_length": len(message)
        }

        self._write_to_jsonl("parsed_hl7.jsonl", log_entry)

    def log_error(
        self,
        error_message: str,
        client_id: Optional[int] = None,
        error_type: str = "UNKNOWN_ERROR",
        details: Optional[Dict] = None
    ) -> None:
        """
        Log error or exception.

        Args:
            error_message: Error message
            client_id: Client identifier (optional)
            error_type: Type of error
            details: Additional error details
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "ERROR",
            "client_id": client_id,
            "error_type": error_type,
            "error_message": error_message,
            "details": details or {}
        }

        with self.write_lock:
            self.stats["errors"] += 1
            self._write_to_jsonl("errors.jsonl", log_entry)

    def log_connection(
        self,
        client_id: int,
        client_address: tuple,
        event: str = "CONNECTED"
    ) -> None:
        """
        Log client connection/disconnection.

        Args:
            client_id: Client identifier
            client_address: Client IP and port tuple
            event: Connection event (CONNECTED, DISCONNECTED)
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "client_id": client_id,
            "client_ip": client_address[0],
            "client_port": client_address[1]
        }

        self._write_to_jsonl("connections.jsonl", log_entry)

    def log_server_event(
        self,
        event: str,
        details: Optional[Dict] = None
    ) -> None:
        """
        Log server-level events.

        Args:
            event: Event name (STARTED, STOPPED, etc.)
            details: Additional event details
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "details": details or {}
        }

        self._write_to_jsonl("server_events.jsonl", log_entry)

    def _write_to_jsonl(self, filename: str, log_entry: Dict) -> None:
        """
        Write log entry to JSONL file.

        Args:
            filename: Log file name
            log_entry: Log entry dictionary
        """
        try:
            date_log_dir = self._get_date_log_dir()
            log_file = date_log_dir / filename

            with self.write_lock:
                with open(log_file, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            print(f"Error writing to log file: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get logging statistics.

        Returns:
            Dictionary containing message counts and data volumes
        """
        return {
            "timestamp": datetime.now().isoformat(),
            **self.stats
        }

    def export_summary(self) -> Dict[str, Any]:
        """
        Export complete logging summary.

        Returns:
            Dictionary with statistics and file locations
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "log_directory": str(self.log_base_dir),
            "statistics": self.get_statistics(),
            "available_logs": {
                "received_messages": (self.log_base_dir / datetime.now().strftime("%Y-%m-%d") / "received_messages.jsonl").exists(),
                "sent_messages": (self.log_base_dir / datetime.now().strftime("%Y-%m-%d") / "sent_messages.jsonl").exists(),
                "parsed_hl7": (self.log_base_dir / datetime.now().strftime("%Y-%m-%d") / "parsed_hl7.jsonl").exists(),
                "errors": (self.log_base_dir / datetime.now().strftime("%Y-%m-%d") / "errors.jsonl").exists(),
                "connections": (self.log_base_dir / datetime.now().strftime("%Y-%m-%d") / "connections.jsonl").exists(),
                "server_events": (self.log_base_dir / datetime.now().strftime("%Y-%m-%d") / "server_events.jsonl").exists()
            }
        }

    def print_stats(self) -> None:
        """Print statistics to console."""
        stats = self.get_statistics()
        print("\n" + "="*60)
        print("HL7 Server Message Statistics")
        print("="*60)
        print(f"Messages Received: {stats['messages_received']}")
        print(f"Messages Sent:     {stats['messages_sent']}")
        print(f"Bytes Received:    {stats['bytes_received']}")
        print(f"Bytes Sent:        {stats['bytes_sent']}")
        print(f"Errors:            {stats['errors']}")
        print("="*60 + "\n")
