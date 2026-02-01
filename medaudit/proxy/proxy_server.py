"""
HTTP-to-HL7 Proxy Server for Medaudit 2.0
AI Agent Instructions:
- This module provides an HTTP server that converts HTTP requests to HL7 messages
- Uses MLLP (Minimal Lower Layer Protocol) for HL7 transport
- Compatible with Burp Suite, OWASP ZAP, and other HTTP proxy tools
"""

import socket
import http.server
import socketserver
from typing import Optional
from datetime import datetime
from config.logging import ProxyLogger


# MLLP framing characters
MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'


class HL7ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that forwards requests to HL7 server."""
    
    # Class-level configuration (set by start_proxy)
    hl7_host: str = "localhost"
    hl7_port: int = 2575
    logger: Optional[ProxyLogger] = None
    
    def log_message(self, format, *args):
        """Override to suppress default logging."""
        pass
    
    def do_POST(self):
        """Handle POST requests by converting to HL7."""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            # Log the HTTP request
            if self.logger:
                self.logger.log_http_request(
                    method="POST",
                    path=self.path,
                    content_length=content_length,
                    client_ip=self.client_address[0]
                )
            
            # Convert to HL7 message (wrap in MLLP)
            hl7_message = self._convert_to_hl7(body)
            
            # Log the conversion
            if self.logger:
                self.logger.log_hl7_conversion(
                    original_length=len(body),
                    hl7_length=len(hl7_message),
                    hl7_message_start=hl7_message[:100].decode('utf-8', errors='ignore')
                )
            
            # Send to HL7 server
            response = self._send_to_hl7_server(hl7_message)
            
            if response:
                # Log success
                if self.logger:
                    self.logger.log_hl7_response(
                        status="success",
                        response_length=len(response),
                        hl7_ack=response[:100]
                    )
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            else:
                error_msg = "Failed to get response from HL7 server"
                if self.logger:
                    self.logger.log_error(error_msg)
                
                self.send_response(502)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(error_msg.encode('utf-8'))
                
        except Exception as e:
            error_msg = f"Proxy error: {str(e)}"
            if self.logger:
                self.logger.log_error(error_msg)
            
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(error_msg.encode('utf-8'))
    
    def do_GET(self):
        """Handle GET requests with usage info."""
        info = f"""Medaudit HTTP-to-HL7 Proxy
============================
Target HL7 Server: {self.hl7_host}:{self.hl7_port}

Usage:
- Send POST requests with HL7 message content in the body
- The proxy will wrap the message in MLLP and forward to the HL7 server
- Response will contain the HL7 ACK message

Example:
  curl -X POST http://localhost:8080/ -d 'MSH|^~\\&|...'
"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(info)))
        self.end_headers()
        self.wfile.write(info.encode('utf-8'))
    
    def _convert_to_hl7(self, body: bytes) -> bytes:
        """Convert HTTP body to MLLP-wrapped HL7 message."""
        # If already starts with MSH|, just wrap in MLLP
        text = body.decode('utf-8', errors='ignore')
        
        if not text.startswith('MSH|'):
            # Create a basic HL7 wrapper
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            text = f"MSH|^~\\&|PROXY|MEDAUDIT|TARGET|DEVICE|{timestamp}||ADT^A01|{timestamp}|P|2.5\r{text}"
        
        return MLLP_START + text.encode('utf-8') + MLLP_END
    
    def _send_to_hl7_server(self, message: bytes) -> Optional[str]:
        """Send MLLP-wrapped message to HL7 server and get response."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(30)
                sock.connect((self.hl7_host, self.hl7_port))
                sock.sendall(message)
                
                # Receive response
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if MLLP_END in response:
                        break
                
                # Parse MLLP response
                if response:
                    # Remove MLLP framing
                    if response.startswith(MLLP_START):
                        response = response[1:]
                    end_idx = response.find(MLLP_END)
                    if end_idx > 0:
                        response = response[:end_idx]
                    return response.decode('utf-8', errors='ignore')
                
                return None
                
        except Exception as e:
            print(f"HL7 server connection error: {e}")
            return None


def start_proxy(
    http_host: str = "localhost",
    http_port: int = 8080,
    hl7_host: str = "localhost",
    hl7_port: int = 2575,
    enable_logging: bool = True,
    log_dir: str = "logs"
):
    """
    Start the HTTP-to-HL7 proxy server.
    
    Args:
        http_host: Host to bind the HTTP server
        http_port: Port for the HTTP server
        hl7_host: Target HL7 server hostname
        hl7_port: Target HL7 server port
        enable_logging: Enable proxy activity logging
        log_dir: Directory for log files
    """
    # Configure the handler
    HL7ProxyHandler.hl7_host = hl7_host
    HL7ProxyHandler.hl7_port = hl7_port
    
    # Setup logging
    if enable_logging:
        HL7ProxyHandler.logger = ProxyLogger(log_dir=log_dir)
    
    # Create and start server
    with socketserver.TCPServer((http_host, http_port), HL7ProxyHandler) as server:
        print(f"HTTP-to-HL7 Proxy started")
        print(f"  HTTP Server: http://{http_host}:{http_port}")
        print(f"  Target HL7:  {hl7_host}:{hl7_port}")
        print(f"  Logging:     {'Enabled' if enable_logging else 'Disabled'}")
        print("\nPress Ctrl+C to stop...")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down proxy...")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='HTTP-to-HL7 Proxy Server')
    parser.add_argument('--host', default='localhost', help='Host for the HTTP proxy server')
    parser.add_argument('--port', type=int, default=8080, help='Port for the HTTP proxy server')
    parser.add_argument('--hl7-host', default='localhost', help='Hostname of the target HL7 server')
    parser.add_argument('--hl7-port', type=int, default=2575, help='Port of the target HL7 server')
    args = parser.parse_args()

    start_proxy(
        http_host=args.host,
        http_port=args.port,
        hl7_host=args.hl7_host,
        hl7_port=args.hl7_port
    )
