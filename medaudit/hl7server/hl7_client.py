"""
HL7 2.x Client for Medaudit

Connects to HL7 servers and sends messages using MLLP protocol.
Can be used for testing, integration, and load testing.
"""

import socket
import ssl
from typing import Optional, Tuple
from datetime import datetime


class HL7Client:
    """HL7 2.x client for sending messages to servers."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 2575,
        use_tls: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        timeout: int = 10,
        verbose: bool = True
    ):
        """
        Initialize HL7 client.

        Args:
            host: Server host
            port: Server port
            use_tls: Use TLS/SSL encryption
            cert_file: Path to client certificate file
            key_file: Path to client key file
            timeout: Socket timeout in seconds
            verbose: Print debug messages
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cert_file = cert_file
        self.key_file = key_file
        self.timeout = timeout
        self.verbose = verbose
        self.socket = None
        self.message_count = 0

    def connect(self) -> bool:
        """
        Connect to HL7 server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)

            if self.verbose:
                print(f"Connecting to {self.host}:{self.port}...")

            self.socket.connect((self.host, self.port))

            # Wrap with TLS if needed
            if self.use_tls:
                context = ssl.create_default_context()
                if self.cert_file:
                    context.load_cert_chain(self.cert_file, self.key_file)
                self.socket = context.wrap_socket(
                    self.socket,
                    server_hostname=self.host
                )

            if self.verbose:
                print(f"✓ Connected to {self.host}:{self.port}")
                print(f"  Encryption: {'TLS/SSL' if self.use_tls else 'Plain TCP'}")

            return True

        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from server."""
        if self.socket:
            try:
                self.socket.close()
                if self.verbose:
                    print("✓ Disconnected from server")
            except:
                pass

    def send_message(self, hl7_message: str) -> Optional[str]:
        """
        Send HL7 message and receive ACK.

        Args:
            hl7_message: HL7 message to send

        Returns:
            ACK message received, or None if error
        """
        if not self.socket:
            print("Error: Not connected to server")
            return None

        try:
            # Wrap message in MLLP frame
            mllp_message = self._wrap_mllp(hl7_message)

            # Send message
            self.socket.sendall(mllp_message)
            self.message_count += 1

            if self.verbose:
                print(f"\n[Message {self.message_count}] Sent {len(hl7_message)} bytes")
                print(f"Message preview: {hl7_message[:80]}...")

            # Receive ACK
            ack = self._receive_mllp()

            if ack:
                if self.verbose:
                    print(f"[Message {self.message_count}] Received ACK:")
                    print(f"ACK preview: {ack[:80]}...")

            return ack

        except Exception as e:
            print(f"Error sending message: {e}")
            return None

    def send_adt_message(
        self,
        patient_id: str = "12345",
        patient_name: str = "Doe^John",
        event_type: str = "A01"
    ) -> Optional[str]:
        """
        Send ADT (Admission/Discharge/Transfer) message.

        Args:
            patient_id: Patient ID
            patient_name: Patient name (format: LastName^FirstName)
            event_type: ADT event type (A01=Admit, A03=Discharge, etc.)

        Returns:
            ACK message received
        """
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        message_id = f"{self.message_count + 1:05d}"

        hl7_message = (
            f"MSH|^~\\&|MEDAUDIT_CLIENT|CLINIC|MEDAUDIT_SERVER|SERVER|{timestamp}||ADT^{event_type}|{message_id}|P|2.5\r"
            f"EVN|{event_type}|{timestamp}\r"
            f"PID|1||{patient_id}||{patient_name}||19800101|M|||123 Main St^^Springfield^IL^62701||555-1234\r"
            f"PV1|1|I|WARD-1^BED-1|A|||123456||INP||||||||ADMISSION"
        )

        return self.send_message(hl7_message)

    def send_orm_message(
        self,
        patient_id: str = "12345",
        order_id: str = "ORD001",
        test_code: str = "CBC"
    ) -> Optional[str]:
        """
        Send ORM (Order) message.

        Args:
            patient_id: Patient ID
            order_id: Order ID
            test_code: Test code

        Returns:
            ACK message received
        """
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        message_id = f"{self.message_count + 1:05d}"

        hl7_message = (
            f"MSH|^~\\&|MEDAUDIT_CLIENT|CLINIC|MEDAUDIT_SERVER|SERVER|{timestamp}||ORM^O01|{message_id}|P|2.5\r"
            f"PID|1||{patient_id}\r"
            f"ORC|NW|{order_id}\r"
            f"OBR|1|{order_id}||{test_code}^Complete Blood Count"
        )

        return self.send_message(hl7_message)

    def send_oru_message(
        self,
        patient_id: str = "12345",
        result_id: str = "RES001",
        test_code: str = "CBC"
    ) -> Optional[str]:
        """
        Send ORU (Observation/Result) message.

        Args:
            patient_id: Patient ID
            result_id: Result ID
            test_code: Test code

        Returns:
            ACK message received
        """
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        message_id = f"{self.message_count + 1:05d}"

        hl7_message = (
            f"MSH|^~\\&|MEDAUDIT_CLIENT|LAB|MEDAUDIT_SERVER|SERVER|{timestamp}||ORU^R01|{message_id}|P|2.5\r"
            f"PID|1||{patient_id}||Doe^Jane\r"
            f"OBR|1|{result_id}||{test_code}^Complete Blood Count|F\r"
            f"OBX|1|NM|WBC^White Blood Cell Count||7.5|K/uL|4.5-11.0|N"
        )

        return self.send_message(hl7_message)

    @staticmethod
    def _wrap_mllp(message: str) -> bytes:
        """Wrap HL7 message in MLLP frame."""
        return b'\x0b' + message.encode('utf-8') + b'\x1c\x0d'

    def _receive_mllp(self, max_bytes: int = 8192) -> Optional[str]:
        """
        Receive and unwrap MLLP frame.

        Args:
            max_bytes: Maximum bytes to receive

        Returns:
            Unwrapped HL7 message or None if error
        """
        try:
            data = self.socket.recv(max_bytes)

            if not data:
                return None

            # Parse MLLP frame
            if len(data) < 3 or data[0] != 0x0B:
                return None

            end_index = data.find(b'\x1c\x0d')
            if end_index == -1:
                return None

            message = data[1:end_index].decode('utf-8', errors='ignore')
            return message

        except socket.timeout:
            print("Error: Socket timeout waiting for ACK")
            return None
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None

    def get_stats(self) -> dict:
        """Get client statistics."""
        return {
            "host": self.host,
            "port": self.port,
            "messages_sent": self.message_count,
            "encrypted": self.use_tls
        }


def create_test_client(
    host: str = "localhost",
    port: int = 2575
) -> HL7Client:
    """Create and connect a test client."""
    client = HL7Client(host=host, port=port, verbose=True)
    client.connect()
    return client
