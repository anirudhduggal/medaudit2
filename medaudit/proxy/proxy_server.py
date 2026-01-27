"""
HTTP-to-HL7 Proxy Server for Medaudit 2.0
AI Agent Instructions:
- This module provides HTTP listener that converts requests to HL7 messages
- Use with Burp/ZAP to send HTTP requests that get converted to HL7 traffic
- Start with start_proxy(host, port, hl7_host, hl7_port)
- Default: HTTP on 8080, HL7 target localhost:2575
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import time

class HL7ProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler that forwards requests as HL7 messages."""

    def __init__(self, hl7_host, hl7_port, *args, **kwargs):
        self.hl7_host = hl7_host
        self.hl7_port = hl7_port
        super().__init__(*args, **kwargs)

    def do_POST(self):
        """Handle POST requests by converting to HL7 and forwarding."""
        try:
            # Read HTTP request body
            content_length = int(self.headers['Content-Length'])
            http_body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

            # Convert HTTP body to HL7 message
            hl7_message = self._create_hl7_message(http_body)

            # Send to HL7 server
            response = self._send_hl7_message(hl7_message)

            # Return response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode())

        except Exception as e:
            self.send_error(500, f"Proxy error: {str(e)}")

    def _create_hl7_message(self, http_body):
        """Create HL7 message from HTTP body."""
        # If body already looks like HL7 (starts with MSH), use as-is
        if http_body.strip().startswith('MSH|'):
            message = http_body.strip()
        else:
            # Create basic HL7 message structure
            # MSH|^~\&|SENDER|FACILITY|RECEIVER|FACILITY|20240126||ADT^A01|MSG001|P|2.5
            timestamp = time.strftime('%Y%m%d%H%M%S')
            message = f"MSH|^~\\&|HTTP_PROXY|MEDAUDIT|HL7_SERVER|MEDICAL_DEVICE|{timestamp}||ADT^A01|MSG001|P|2.5\r"
            message += f"PID|1||{http_body}|||||\r"  # Simple PID segment with body as ID

        # Wrap in MLLP (Minimal Lower Layer Protocol)
        # <VT>message<FS><CR>
        mllp_message = f"\x0b{message}\x1c\r"

        return mllp_message

    def _send_hl7_message(self, message):
        """Send HL7 message to target server and return response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # 30 second timeout for remote connections
            sock.connect((self.hl7_host, self.hl7_port))

            # Send message
            sock.sendall(message.encode())

            # Try to receive response (some HL7 servers respond)
            response = b""
            try:
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
                    response += data
                    # Basic check for end of MLLP message
                    if b'\x1c\r' in response:
                        break
            except socket.timeout:
                # Timeout is OK - many HL7 servers don't respond
                pass

            sock.close()

            # Extract message from MLLP wrapper if present
            if response.startswith(b'\x0b') and b'\x1c\r' in response:
                start = response.find(b'\x0b') + 1
                end = response.find(b'\x1c\r')
                if end > start:
                    return response[start:end].decode('utf-8', errors='ignore')

            return response.decode('utf-8', errors='ignore') if response else "Message sent successfully"

        except socket.gaierror as e:
            return f"HL7 connection error: Could not resolve hostname '{self.hl7_host}' - {e}"
        except socket.timeout as e:
            return f"HL7 connection timeout: Server at {self.hl7_host}:{self.hl7_port} did not respond within 30 seconds"
        except ConnectionRefusedError as e:
            return f"HL7 connection refused: Server at {self.hl7_host}:{self.hl7_port} is not accepting connections"
        except Exception as e:
            return f"HL7 send error: {str(e)}"

    def log_message(self, format, *args):
        """Override to reduce noise in output."""
        pass

def start_proxy(http_host='localhost', http_port=8080, hl7_host='localhost', hl7_port=2575):
    """Start the HTTP-to-HL7 proxy server."""
    # Validate HL7 target connectivity
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(5)
        result = test_sock.connect_ex((hl7_host, hl7_port))
        test_sock.close()
        
        if result != 0:
            print(f"Warning: Cannot connect to HL7 server at {hl7_host}:{hl7_port}")
            print("Make sure the target HL7 server is running and accessible")
            print("Continuing anyway - connections will be attempted when requests arrive")
        else:
            print(f"✓ HL7 server at {hl7_host}:{hl7_port} is reachable")
    except Exception as e:
        print(f"Warning: Could not test HL7 server connectivity: {e}")
        print("Continuing anyway - connections will be attempted when requests arrive")

    def handler_factory(*args, **kwargs):
        return HL7ProxyHandler(hl7_host, hl7_port, *args, **kwargs)

    server = HTTPServer((http_host, http_port), handler_factory)

    print(f"HTTP-to-HL7 Proxy started on http://{http_host}:{http_port}")
    print(f"Forwarding to HL7 server at {hl7_host}:{hl7_port}")
    print("Send HTTP POST requests to convert and forward as HL7 messages")
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nProxy stopped")
        server.server_close()