# Medaudit HL7 Fuzzer - Malicious Server
# A malicious HL7 server for testing medical device robustness

"""
HL7 Malicious Server

This module implements a malicious HL7/MLLP server designed to test the robustness
and security of medical devices that connect to it. It simulates various attack
scenarios to identify vulnerabilities in HL7 client implementations.

Attack Categories:
1. ACK Manipulation - No ACK, broken ACK, delayed ACK, flood ACK
2. Protocol Violations - Invalid MLLP framing, encoding issues
3. Payload Attacks - Overflow responses, injection payloads
4. Connection Attacks - Drops, slow drip, keep-alive abuse

Usage:
    from medaudit.fuzzer.malicious_server import MaliciousHL7Server
    
    server = MaliciousHL7Server(port=2575)
    server.set_attack_mode("no_ack")
    server.start()
"""

import socket
import ssl
import threading
import time
import random
import string
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# MLLP Protocol Constants
MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'


class AttackMode(Enum):
    """Available attack modes for the malicious server."""
    NORMAL = "normal"                    # Normal ACK response (baseline)
    NO_ACK = "no_ack"                    # Don't send any ACK
    DELAYED_ACK = "delayed_ack"          # Send ACK after long delay
    BROKEN_ACK = "broken_ack"            # Send malformed ACK message
    FLOOD_ACK = "flood_ack"              # Send multiple ACK messages
    PARTIAL_ACK = "partial_ack"          # Send incomplete ACK (no MLLP end)
    WRONG_MLLP = "wrong_mllp"            # Wrong MLLP framing
    OVERFLOW_ACK = "overflow_ack"        # ACK with huge payload
    INJECTION_ACK = "injection_ack"      # ACK with injection payloads
    SLOW_DRIP = "slow_drip"              # Send response byte by byte
    CONNECTION_DROP = "connection_drop"  # Drop connection mid-response
    RESET_CONNECTION = "reset_connection" # RST the connection
    RANDOM_DATA = "random_data"          # Send random binary data
    REPLAY_REQUEST = "replay_request"    # Echo back the request
    ENCODING_ATTACK = "encoding_attack"  # Invalid encoding characters
    NEGATIVE_ACK_FLOOD = "nak_flood"     # Flood with negative ACKs
    CUSTOM = "custom"                    # Custom response handler


@dataclass
class AttackConfig:
    """Configuration for attack behavior."""
    mode: AttackMode = AttackMode.NORMAL
    delay_seconds: float = 0.0           # Delay before response
    flood_count: int = 100               # Number of messages for flood attacks
    flood_delay_ms: int = 10             # Delay between flood messages
    overflow_size: int = 1_000_000       # Size for overflow attacks
    slow_drip_delay_ms: int = 100        # Delay between bytes for slow drip
    drop_after_bytes: int = 50           # Bytes to send before dropping
    custom_response: Optional[bytes] = None  # Custom response data
    custom_handler: Optional[Callable] = None  # Custom response function
    injection_payloads: List[str] = field(default_factory=list)
    randomize: bool = False              # Randomize attack on each request
    log_requests: bool = True            # Log incoming requests


@dataclass
class ConnectionLog:
    """Log entry for a client connection."""
    timestamp: datetime
    client_address: tuple
    request: bytes
    attack_mode: AttackMode
    response_sent: bool
    error: Optional[str] = None


class MaliciousHL7Server:
    """
    Malicious HL7/MLLP server for security testing.
    
    This server simulates various attack scenarios to test how medical
    devices handle malicious or unexpected server behavior.
    
    Example:
        >>> server = MaliciousHL7Server(port=2575)
        >>> server.set_attack_mode(AttackMode.NO_ACK)
        >>> server.start()
        >>> # Connect your medical device to test
        >>> server.stop()
        >>> print(server.get_logs())
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2575,
        use_tls: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None
    ):
        """
        Initialize the malicious server.
        
        Args:
            host: Bind address
            port: Listen port
            use_tls: Enable TLS
            cert_file: TLS certificate file
            key_file: TLS private key file
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cert_file = cert_file
        self.key_file = key_file
        
        self.config = AttackConfig()
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.connection_logs: List[ConnectionLog] = []
        self._lock = threading.Lock()
        
        # Predefined injection payloads
        self.injection_payloads = [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "'; DROP TABLE patients;--",
            "%n%n%n%n%n",
            "../../../etc/passwd",
            "${7*7}",
            "{{constructor.constructor('return this')()}}",
            "\x00\x00\x00\x00",
            "A" * 10000,
        ]
    
    def set_attack_mode(self, mode: AttackMode, **kwargs):
        """
        Set the attack mode and configuration.
        
        Args:
            mode: Attack mode to use
            **kwargs: Additional configuration options
        """
        self.config.mode = mode
        
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        logger.info(f"Attack mode set to: {mode.value}")
    
    def set_custom_handler(self, handler: Callable[[bytes, socket.socket], None]):
        """
        Set a custom response handler.
        
        Args:
            handler: Function(request_data, client_socket) -> None
        """
        self.config.mode = AttackMode.CUSTOM
        self.config.custom_handler = handler
    
    def start(self):
        """Start the malicious server."""
        if self.running:
            logger.warning("Server already running")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        logger.info(f"Malicious HL7 server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        if self.server_thread:
            self.server_thread.join(timeout=5)
        logger.info("Malicious HL7 server stopped")
    
    def get_logs(self) -> List[Dict[str, Any]]:
        """Get connection logs."""
        with self._lock:
            return [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "client": f"{log.client_address[0]}:{log.client_address[1]}",
                    "request_size": len(log.request),
                    "request_preview": log.request[:200].decode('utf-8', errors='ignore'),
                    "attack_mode": log.attack_mode.value,
                    "response_sent": log.response_sent,
                    "error": log.error
                }
                for log in self.connection_logs
            ]
    
    def clear_logs(self):
        """Clear connection logs."""
        with self._lock:
            self.connection_logs.clear()
    
    def _server_loop(self):
        """Main server loop."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            
            if self.use_tls and self.cert_file and self.key_file:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.cert_file, self.key_file)
                self.server_socket = context.wrap_socket(
                    self.server_socket, server_side=True
                )
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle a client connection."""
        request_data = b""
        response_sent = False
        error = None
        
        # Determine attack mode (possibly randomize)
        attack_mode = self.config.mode
        if self.config.randomize:
            attack_mode = random.choice(list(AttackMode))
        
        try:
            client_socket.settimeout(30)
            
            # Receive the request
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                if MLLP_END in request_data:
                    break
            
            if self.config.log_requests:
                logger.info(f"Received {len(request_data)} bytes from {client_address}")
            
            # Apply delay if configured
            if self.config.delay_seconds > 0:
                time.sleep(self.config.delay_seconds)
            
            # Execute attack
            response_sent = self._execute_attack(
                attack_mode, request_data, client_socket
            )
        
        except Exception as e:
            error = str(e)
            logger.error(f"Client handler error: {e}")
        
        finally:
            # Log the connection
            with self._lock:
                self.connection_logs.append(ConnectionLog(
                    timestamp=datetime.now(),
                    client_address=client_address,
                    request=request_data,
                    attack_mode=attack_mode,
                    response_sent=response_sent,
                    error=error
                ))
            
            try:
                client_socket.close()
            except Exception:
                pass
    
    def _execute_attack(
        self, 
        mode: AttackMode, 
        request: bytes, 
        sock: socket.socket
    ) -> bool:
        """
        Execute the configured attack.
        
        Returns:
            True if response was sent
        """
        try:
            if mode == AttackMode.NORMAL:
                return self._send_normal_ack(request, sock)
            
            elif mode == AttackMode.NO_ACK:
                return self._attack_no_ack(sock)
            
            elif mode == AttackMode.DELAYED_ACK:
                return self._attack_delayed_ack(request, sock)
            
            elif mode == AttackMode.BROKEN_ACK:
                return self._attack_broken_ack(request, sock)
            
            elif mode == AttackMode.FLOOD_ACK:
                return self._attack_flood_ack(request, sock)
            
            elif mode == AttackMode.PARTIAL_ACK:
                return self._attack_partial_ack(request, sock)
            
            elif mode == AttackMode.WRONG_MLLP:
                return self._attack_wrong_mllp(request, sock)
            
            elif mode == AttackMode.OVERFLOW_ACK:
                return self._attack_overflow_ack(request, sock)
            
            elif mode == AttackMode.INJECTION_ACK:
                return self._attack_injection_ack(request, sock)
            
            elif mode == AttackMode.SLOW_DRIP:
                return self._attack_slow_drip(request, sock)
            
            elif mode == AttackMode.CONNECTION_DROP:
                return self._attack_connection_drop(request, sock)
            
            elif mode == AttackMode.RESET_CONNECTION:
                return self._attack_reset_connection(sock)
            
            elif mode == AttackMode.RANDOM_DATA:
                return self._attack_random_data(sock)
            
            elif mode == AttackMode.REPLAY_REQUEST:
                return self._attack_replay_request(request, sock)
            
            elif mode == AttackMode.ENCODING_ATTACK:
                return self._attack_encoding(request, sock)
            
            elif mode == AttackMode.NEGATIVE_ACK_FLOOD:
                return self._attack_nak_flood(request, sock)
            
            elif mode == AttackMode.CUSTOM:
                if self.config.custom_handler:
                    self.config.custom_handler(request, sock)
                    return True
                elif self.config.custom_response:
                    sock.sendall(self.config.custom_response)
                    return True
                return False
            
            return False
        
        except Exception as e:
            logger.error(f"Attack execution error: {e}")
            return False
    
    def _parse_message_control_id(self, request: bytes) -> str:
        """Extract message control ID from HL7 request."""
        try:
            data = request.decode('utf-8', errors='ignore')
            if MLLP_START in request:
                data = data[1:]
            
            # Find MSH segment
            for line in data.split('\r'):
                if line.startswith('MSH|'):
                    fields = line.split('|')
                    if len(fields) > 9:
                        return fields[9]  # MSH-10 is message control ID
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"
    
    def _build_ack(self, control_id: str, ack_code: str = "AA", error_msg: str = "") -> bytes:
        """Build a standard ACK message."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        ack = f"MSH|^~\\&|MALICIOUS|SERVER|CLIENT|APP|{timestamp}||ACK|{timestamp}|P|2.5\r"
        ack += f"MSA|{ack_code}|{control_id}|{error_msg}\r"
        
        return MLLP_START + ack.encode('utf-8') + MLLP_END
    
    def _send_normal_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send a normal ACK response."""
        control_id = self._parse_message_control_id(request)
        ack = self._build_ack(control_id, "AA")
        sock.sendall(ack)
        return True
    
    def _attack_no_ack(self, sock: socket.socket) -> bool:
        """Don't send any response - test client timeout handling."""
        logger.debug("NO_ACK: Withholding response")
        # Just don't send anything
        time.sleep(0.1)  # Brief pause before closing
        return False
    
    def _attack_delayed_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send ACK after a long delay - test timeout handling."""
        delay = self.config.delay_seconds or 30
        logger.debug(f"DELAYED_ACK: Waiting {delay}s before response")
        time.sleep(delay)
        return self._send_normal_ack(request, sock)
    
    def _attack_broken_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send various malformed ACK messages."""
        control_id = self._parse_message_control_id(request)
        
        broken_acks = [
            # Missing MSA segment
            MLLP_START + f"MSH|^~\\&|MAL|SRV|CLT|APP|{datetime.now().strftime('%Y%m%d%H%M%S')}||ACK|X|P|2.5\r".encode() + MLLP_END,
            
            # Invalid ACK code
            self._build_ack(control_id, "XX"),
            
            # Missing fields
            MLLP_START + b"MSH|^~\\&\rMSA|AA\r" + MLLP_END,
            
            # Wrong delimiter
            MLLP_START + f"MSH!^~\\&!MAL!SRV!{datetime.now().strftime('%Y%m%d%H%M%S')}!!ACK\rMSA!AA!{control_id}\r".encode() + MLLP_END,
            
            # Truncated message
            MLLP_START + b"MSH|^~\\&|TRUNC" + MLLP_END,
            
            # Empty ACK
            MLLP_START + MLLP_END,
            
            # Just the word ACK
            MLLP_START + b"ACK" + MLLP_END,
            
            # Binary garbage in ACK
            MLLP_START + b"MSH|^~\\&|\x00\x01\x02\x03||\r" + MLLP_END,
        ]
        
        chosen = random.choice(broken_acks)
        sock.sendall(chosen)
        return True
    
    def _attack_flood_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send a flood of ACK messages."""
        control_id = self._parse_message_control_id(request)
        count = self.config.flood_count
        delay = self.config.flood_delay_ms / 1000
        
        logger.debug(f"FLOOD_ACK: Sending {count} ACKs")
        
        for i in range(count):
            try:
                ack = self._build_ack(f"{control_id}_{i}", "AA")
                sock.sendall(ack)
                if delay > 0:
                    time.sleep(delay)
            except Exception:
                break
        
        return True
    
    def _attack_partial_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send incomplete ACK without MLLP end marker."""
        control_id = self._parse_message_control_id(request)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Send start and message but no end
        partial = MLLP_START + f"MSH|^~\\&|MAL|SRV|CLT|APP|{timestamp}||ACK|{timestamp}|P|2.5\rMSA|AA|{control_id}\r".encode()
        sock.sendall(partial)
        
        # Keep connection open
        time.sleep(5)
        return True
    
    def _attack_wrong_mllp(self, request: bytes, sock: socket.socket) -> bool:
        """Send response with wrong MLLP framing."""
        control_id = self._parse_message_control_id(request)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        wrong_framings = [
            # No MLLP framing at all
            f"MSH|^~\\&|MAL|SRV|CLT|APP|{timestamp}||ACK|{timestamp}|P|2.5\rMSA|AA|{control_id}\r".encode(),
            
            # Wrong start byte
            b'\x02' + f"MSH|^~\\&|MAL|SRV|{timestamp}||ACK\rMSA|AA|{control_id}\r".encode() + MLLP_END,
            
            # Wrong end bytes
            MLLP_START + f"MSH|^~\\&|MAL|SRV|{timestamp}||ACK\rMSA|AA|{control_id}\r".encode() + b'\x03\x04',
            
            # Double framing
            MLLP_START + MLLP_START + f"MSH|^~\\&|MAL|{timestamp}||ACK\rMSA|AA|{control_id}\r".encode() + MLLP_END + MLLP_END,
            
            # Multiple start bytes
            MLLP_START * 10 + f"MSH|^~\\&|MAL|{timestamp}||ACK\rMSA|AA|{control_id}\r".encode() + MLLP_END,
        ]
        
        sock.sendall(random.choice(wrong_framings))
        return True
    
    def _attack_overflow_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send ACK with huge payload to test buffer overflow."""
        control_id = self._parse_message_control_id(request)
        size = self.config.overflow_size
        
        # Build oversized ACK
        padding = "A" * size
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        overflow_ack = MLLP_START + f"MSH|^~\\&|MAL|SRV|CLT|APP|{timestamp}||ACK|{timestamp}|P|2.5\rMSA|AA|{control_id}|{padding}\r".encode() + MLLP_END
        
        logger.debug(f"OVERFLOW_ACK: Sending {len(overflow_ack)} byte response")
        sock.sendall(overflow_ack)
        return True
    
    def _attack_injection_ack(self, request: bytes, sock: socket.socket) -> bool:
        """Send ACK with injection payloads."""
        control_id = self._parse_message_control_id(request)
        payloads = self.config.injection_payloads or self.injection_payloads
        payload = random.choice(payloads)
        
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Inject payload in various fields
        injected_ack = MLLP_START + f"MSH|^~\\&|{payload}|{payload}|CLT|APP|{timestamp}||ACK|{timestamp}|P|2.5\rMSA|AA|{control_id}|{payload}\rERR|{payload}\r".encode() + MLLP_END
        
        sock.sendall(injected_ack)
        return True
    
    def _attack_slow_drip(self, request: bytes, sock: socket.socket) -> bool:
        """Send response byte by byte with delays."""
        control_id = self._parse_message_control_id(request)
        ack = self._build_ack(control_id, "AA")
        delay = self.config.slow_drip_delay_ms / 1000
        
        logger.debug(f"SLOW_DRIP: Sending {len(ack)} bytes with {delay}s delay each")
        
        for byte in ack:
            try:
                sock.send(bytes([byte]))
                time.sleep(delay)
            except Exception:
                return False
        
        return True
    
    def _attack_connection_drop(self, request: bytes, sock: socket.socket) -> bool:
        """Send partial response then drop connection."""
        control_id = self._parse_message_control_id(request)
        ack = self._build_ack(control_id, "AA")
        
        # Send partial data
        drop_at = min(self.config.drop_after_bytes, len(ack))
        sock.send(ack[:drop_at])
        
        logger.debug(f"CONNECTION_DROP: Sent {drop_at} bytes, dropping connection")
        
        # Abruptly close
        sock.close()
        return False
    
    def _attack_reset_connection(self, sock: socket.socket) -> bool:
        """Send TCP RST to reset connection."""
        logger.debug("RESET_CONNECTION: Sending RST")
        
        # Set SO_LINGER to force RST
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 
                       struct.pack('ii', 1, 0))
        sock.close()
        return False
    
    def _attack_random_data(self, sock: socket.socket) -> bool:
        """Send random binary data."""
        size = random.randint(100, 10000)
        data = bytes(random.getrandbits(8) for _ in range(size))
        
        logger.debug(f"RANDOM_DATA: Sending {size} random bytes")
        sock.sendall(data)
        return True
    
    def _attack_replay_request(self, request: bytes, sock: socket.socket) -> bool:
        """Echo back the request as the response."""
        logger.debug("REPLAY_REQUEST: Echoing request back")
        sock.sendall(request)
        return True
    
    def _attack_encoding(self, request: bytes, sock: socket.socket) -> bool:
        """Send response with invalid encoding characters."""
        control_id = self._parse_message_control_id(request)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Various encoding attacks
        encoding_attacks = [
            # Invalid UTF-8 sequences
            MLLP_START + b"MSH|^~\\&|\xff\xfe|SRV|CLT|" + timestamp.encode() + b"||ACK\rMSA|AA|" + control_id.encode() + b"\r" + MLLP_END,
            
            # Null bytes
            MLLP_START + f"MSH|^~\\&|MAL\x00|SRV\x00|CLT|{timestamp}||ACK\rMSA|AA|{control_id}\x00\r".encode() + MLLP_END,
            
            # Control characters
            MLLP_START + f"MSH|^~\\&|\x01\x02\x03|SRV|{timestamp}||ACK\rMSA|AA|{control_id}\r".encode() + MLLP_END,
            
            # Mixed encodings (UTF-8 + Latin-1)
            MLLP_START + "MSH|^~\\&|Mäl|Sërvér|".encode('utf-8') + b"\xe0\xe1\xe2|" + timestamp.encode() + b"||ACK\rMSA|AA|" + control_id.encode() + b"\r" + MLLP_END,
            
            # Overlong UTF-8
            MLLP_START + b"MSH|^~\\&|\xc0\xaf|SRV|" + timestamp.encode() + b"||ACK\rMSA|AA|" + control_id.encode() + b"\r" + MLLP_END,
        ]
        
        sock.sendall(random.choice(encoding_attacks))
        return True
    
    def _attack_nak_flood(self, request: bytes, sock: socket.socket) -> bool:
        """Flood with negative acknowledgments."""
        control_id = self._parse_message_control_id(request)
        count = self.config.flood_count
        
        error_messages = [
            "Application error",
            "Message rejected",
            "Unknown segment",
            "Required field missing",
            "Data type error",
            "Table value not found",
            "Unsupported message type",
            "Application internal error",
            "Sequence number error",
            "' OR '1'='1; DROP TABLE messages;--",  # Sneaky injection
        ]
        
        logger.debug(f"NAK_FLOOD: Sending {count} negative ACKs")
        
        for i in range(count):
            try:
                error = random.choice(error_messages)
                nak = self._build_ack(f"{control_id}_{i}", "AE", error)
                sock.sendall(nak)
                time.sleep(self.config.flood_delay_ms / 1000)
            except Exception:
                break
        
        return True


# Import struct for RST attack
import struct


def create_attack_sequence(modes: List[AttackMode]) -> Callable:
    """
    Create a custom handler that cycles through attack modes.
    
    Args:
        modes: List of attack modes to cycle through
        
    Returns:
        Handler function for the server
    """
    index = [0]  # Mutable to track position
    
    def handler(request: bytes, sock: socket.socket):
        mode = modes[index[0] % len(modes)]
        index[0] += 1
        
        # Create temporary server to execute attack
        temp = MaliciousHL7Server.__new__(MaliciousHL7Server)
        temp.config = AttackConfig(mode=mode)
        temp.injection_payloads = []
        temp._execute_attack(mode, request, sock)
    
    return handler


# Convenience functions for common attack scenarios

def quick_test_no_ack(host: str = "0.0.0.0", port: int = 2575) -> MaliciousHL7Server:
    """Start a server that never sends ACKs."""
    server = MaliciousHL7Server(host, port)
    server.set_attack_mode(AttackMode.NO_ACK)
    server.start()
    return server


def quick_test_broken_ack(host: str = "0.0.0.0", port: int = 2575) -> MaliciousHL7Server:
    """Start a server that sends broken ACKs."""
    server = MaliciousHL7Server(host, port)
    server.set_attack_mode(AttackMode.BROKEN_ACK)
    server.start()
    return server


def quick_test_flood(host: str = "0.0.0.0", port: int = 2575, count: int = 100) -> MaliciousHL7Server:
    """Start a server that floods with ACKs."""
    server = MaliciousHL7Server(host, port)
    server.set_attack_mode(AttackMode.FLOOD_ACK, flood_count=count)
    server.start()
    return server


def quick_test_random(host: str = "0.0.0.0", port: int = 2575) -> MaliciousHL7Server:
    """Start a server that uses random attacks."""
    server = MaliciousHL7Server(host, port)
    server.config.randomize = True
    server.start()
    return server
