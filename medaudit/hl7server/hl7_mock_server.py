"""
HL7 2.x Mock Server Implementation

This server:
- Listens for MLLP-wrapped HL7 messages (start byte 0x0b, end bytes 0x1c 0x0d)
- Parses incoming HL7 messages
- Generates and sends HL7 ACK responses
- Supports optional TLS/SSL encryption
- Non-encrypted by default
- Logs all transactions

MLLP Protocol:
- Start: 0x0B (vertical tab)
- Message: UTF-8 encoded HL7 message
- End: 0x1C 0x0D (file separator + carriage return)
"""

import socket
import ssl
import threading
import logging
from datetime import datetime
from typing import Optional, Callable
import json
from pathlib import Path
from .message_logger import MessageLogger


class HL7Server:
    """Mock HL7 2.x server that acknowledges messages."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 2575,
        use_tls: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        log_dir: str = "logs",
        message_callback: Optional[Callable] = None,
        verbose: bool = True
    ):
        """
        Initialize HL7 server.

        Args:
            host: Server hostname/IP (default: localhost)
            port: Server port (default: 2575)
            use_tls: Enable TLS/SSL encryption (default: False)
            cert_file: Path to SSL certificate file (required if use_tls=True)
            key_file: Path to SSL key file (required if use_tls=True)
            log_dir: Directory for logging messages (default: logs)
            message_callback: Optional callback function for received messages
            verbose: Print status messages to console (default: True)
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cert_file = cert_file
        self.key_file = key_file
        self.message_callback = message_callback
        self.verbose = verbose

        # Setup logging
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = self._setup_logger()
        
        # Enhanced message logging
        self.message_logger = MessageLogger(log_base_dir=log_dir)

        # Server state
        self.server_socket = None
        self.running = False
        self.client_count = 0
        self.message_count = 0

    def _setup_logger(self) -> logging.Logger:
        """Setup logging for the server."""
        logger = logging.getLogger("HL7Server")
        logger.setLevel(logging.INFO)

        # Create handlers
        log_file = self.log_dir / f"hl7_server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        console_handler = logging.StreamHandler()

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        if self.verbose:
            logger.addHandler(console_handler)

        return logger

    def start(self):
        """Start the HL7 server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)  # Allow accept() to be interrupted on stop()
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            encryption_status = "TLS/SSL enabled" if self.use_tls else "Non-encrypted"
            self.logger.info(f"HL7 Server started on {self.host}:{self.port} - {encryption_status}")
            
            # Log server event
            self.message_logger.log_server_event(
                "SERVER_STARTED",
                {
                    "host": self.host,
                    "port": self.port,
                    "encryption": encryption_status
                }
            )

            if self.verbose:
                print(f"✓ HL7 Server running on {self.host}:{self.port} ({encryption_status})")

            # Start accepting connections in background thread
            server_thread = threading.Thread(target=self._accept_connections, daemon=True)
            server_thread.start()

        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            raise

    def stop(self):
        """Stop the HL7 server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Log server event
        self.message_logger.log_server_event("SERVER_STOPPED")
        self.message_logger.print_stats()
        
        self.logger.info("HL7 Server stopped")
        if self.verbose:
            print("✓ HL7 Server stopped")

    def _accept_connections(self):
        """Accept and handle client connections."""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.client_count += 1
                client_id = self.client_count

                self.logger.info(f"Client {client_id} connected from {client_address[0]}:{client_address[1]}")

                # Log connection
                self.message_logger.log_connection(client_id, client_address, "CONNECTED")

                # Wrap socket with TLS if enabled
                if self.use_tls:
                    try:
                        client_socket = self._wrap_with_tls(client_socket)
                    except Exception as e:
                        self.logger.error(f"TLS handshake failed for client {client_id}: {e}")
                        client_socket.close()
                        continue

                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address, client_id),
                    daemon=True
                )
                client_thread.start()

            except socket.timeout:
                # Expected: 1-second timeout fires so we can re-check self.running
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error accepting connection: {e}")

    def _wrap_with_tls(self, client_socket):
        """Wrap socket with TLS/SSL."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.cert_file, self.key_file)
        return context.wrap_socket(client_socket, server_side=True)

    def _handle_client(self, client_socket, client_address, client_id):
        """Handle individual client connection."""
        # Set receive timeout to allow for graceful connection handling
        client_socket.settimeout(300)  # 5 minute timeout
        buffer = b""
        
        try:
            while self.running:
                # Receive MLLP-wrapped HL7 message
                data = client_socket.recv(4096)

                if not data:
                    break

                buffer += data

                # Process all complete MLLP frames in the buffer
                while b'\x0b' in buffer and b'\x1c\x0d' in buffer:
                    start_index = buffer.find(b'\x0b')
                    end_index = buffer.find(b'\x1c\x0d')

                    if end_index < start_index:
                        # Malformed buffer, discard everything up to the next start byte
                        buffer = buffer[start_index:]
                        continue

                    mllp_frame = buffer[start_index:end_index + 2]
                    buffer = buffer[end_index + 2:]

                    hl7_message = self._parse_mllp_frame(mllp_frame)

                    if hl7_message:
                        self.message_count += 1
                        self.logger.info(f"Client {client_id}: Received HL7 message #{self.message_count}")

                        # Log message details
                        self._log_hl7_message(hl7_message, client_id, "RECEIVED")
                        
                        # Extract message info for enhanced logging
                        message_info = self._extract_message_info(hl7_message)
                        self.message_logger.log_received_message(
                            hl7_message,
                            client_id,
                            client_address,
                            message_control_id=message_info.get("message_id"),
                            message_type=message_info.get("message_type")
                        )

                        # Call callback if provided
                        if self.message_callback:
                            try:
                                self.message_callback(hl7_message, client_address)
                            except Exception as e:
                                self.logger.error(f"Error in message callback: {e}")

                        self.logger.info(f"Client {client_id}: Generating ACK")
                        # Generate and send ACK
                        ack_message = self._generate_ack(hl7_message)
                        mllp_ack = self._wrap_mllp_frame(ack_message)
    
                        try:
                            self.logger.info(f"Client {client_id}: Sending ACK")
                            client_socket.sendall(mllp_ack)
                            self.logger.info(f"Client {client_id}: ACK sent successfully")
                            self._log_hl7_message(ack_message, client_id, "SENT")
                            self.logger.info(f"Client {client_id}: ACK send logged")
                        except Exception as e:
                            self.logger.error(f"Failed to send ACK to client {client_id}: {e}")
                            self.message_logger.log_error(
                                f"Failed to send ACK: {e}",
                                client_id=client_id,
                                error_type="ACK_SEND_FAILED"
                            )
        except Exception as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
        finally:
            try:
                client_socket.close()
                self.logger.info(f"Client {client_id} disconnected")
                self.message_logger.log_connection(client_id, client_address, "DISCONNECTED")
            except:
                pass

    @staticmethod
    def _parse_mllp_frame(data: bytes) -> Optional[str]:
        """
        Parse MLLP-wrapped HL7 message.

        MLLP format:
        - Start byte: 0x0B (vertical tab)
        - Message: HL7 message
        - End bytes: 0x1C 0x0D (file separator + carriage return)
        """
        if len(data) < 3:
            return None

        # Check for MLLP start byte (0x0B)
        if data[0] != 0x0B:
            return None

        # Find end bytes (0x1C 0x0D)
        end_index = data.find(b'\x1c\x0d')
        if end_index == -1:
            return None

        # Extract message between start and end
        message_bytes = data[1:end_index]
        return message_bytes.decode('utf-8', errors='ignore')

    @staticmethod
    def _wrap_mllp_frame(message: str) -> bytes:
        """Wrap HL7 message in MLLP frame."""
        return b'\x0b' + message.encode('utf-8') + b'\x1c\x0d'

    @staticmethod
    def _generate_ack(hl7_message: str) -> str:
        """
        Generate HL7 ACK (acknowledgment) message.

        Extracts message control ID from MSH segment and creates ACK.
        """
        try:
            # Parse MSH segment
            segments = hl7_message.split('\r')
            msh_segment = segments[0]

            # Extract message control ID (field 10 in MSH)
            msh_fields = msh_segment.split('|')
            if len(msh_fields) > 9:
                message_id = msh_fields[9]
            else:
                message_id = "UNKNOWN"

            # Extract timestamp
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

            # Create ACK message
            ack = (
                f"MSH|^~\\&|MEDAUDIT_MOCK_SERVER|MOCK|TEST|TEST|{timestamp}||ACK|{message_id}|P|2.5\r"
                f"MSA|AA|{message_id}|Message received successfully"
            )

            return ack

        except Exception as e:
            # Fallback ACK if parsing fails
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            return f"MSH|^~\\&|MEDAUDIT_MOCK_SERVER|MOCK|TEST|TEST|{timestamp}||ACK|UNKNOWN|P|2.5\rMSA|AA|UNKNOWN|Error generating ACK"

    def _log_hl7_message(self, message: str, client_id: int, direction: str):
        """Log HL7 message to JSON file."""
        try:
            log_file = self.log_dir / "hl7_messages.jsonl"

            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "client_id": client_id,
                "direction": direction,
                "message": message[:500],  # First 500 chars
                "message_length": len(message)
            }

            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            self.logger.error(f"Failed to log message: {e}")

    def get_stats(self) -> dict:
        """Get server statistics."""
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "encrypted": self.use_tls,
            "clients_connected": self.client_count,
            "messages_received": self.message_count,
            "logger_stats": self.message_logger.get_statistics()
        }

    def _extract_message_info(self, hl7_message: str) -> dict:
        """Extract key information from HL7 message."""
        try:
            segments = hl7_message.split('\r')
            msh_segment = segments[0]
            msh_fields = msh_segment.split('|')

            return {
                "message_id": msh_fields[9] if len(msh_fields) > 9 else "UNKNOWN",
                "message_type": msh_fields[8] if len(msh_fields) > 8 else "UNKNOWN"
            }
        except:
            return {"message_id": "UNKNOWN", "message_type": "UNKNOWN"}
