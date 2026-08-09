"""
HTTP to MLLP Converter for Medaudit 2.0

This module provides an HTTP server that receives HTTP requests and forwards them
as MLLP-wrapped messages to an HL7 server.

Usage:
    1. Start the server: python -m medaudit proxy --port 3000 --hl7-host target_device --hl7-port 2575
    2. Send HTTP POST requests to http://localhost:3000 with your message in the body
    3. The server wraps the body in MLLP framing and forwards to the HL7 server
    4. Returns the HL7 ACK response
"""

import socket
import http.server
import socketserver
import urllib.parse
from typing import Optional
from datetime import datetime
from medaudit.config.logging import ProxyLogger


# MLLP framing characters
MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'


class HL7ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that converts requests to MLLP-wrapped HL7 messages."""
    
    # Class-level configuration (set by start_proxy)
    hl7_host: str = "localhost"
    hl7_port: int = 2575
    logger: Optional[ProxyLogger] = None
    
    def log_message(self, format, *args):
        """Override to suppress default logging."""
        pass
    
    def do_CONNECT(self):
        """Handle CONNECT requests for HTTPS tunneling (pass through)."""
        # For HTTPS, just tunnel the connection without modification
        self.send_response(200, 'Connection Established')
        self.end_headers()
        
    def do_GET(self):
        """Handle GET requests through the proxy."""
        self._proxy_request('GET')
    
    def do_POST(self):
        """Handle POST requests through the proxy."""
        self._proxy_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests through the proxy."""
        self._proxy_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests through the proxy."""
        self._proxy_request('DELETE')
    
    def _proxy_request(self, method: str):
        """
        Handle an HTTP request by converting it to MLLP format.
        
        Reads the HTTP request body, wraps it in MLLP framing,
        forwards to the HL7 server, and returns the HL7 ACK response.
        """
        try:
            # Read request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            
            # Parse the request URL
            parsed_url = urllib.parse.urlparse(self.path)
            
            # Log the intercepted request
            if self.logger:
                self.logger.log_http_request(
                    method=method,
                    path=self.path,
                    content_length=content_length,
                    client_ip=self.client_address[0]
                )
            
            # Convert HTTP request to HL7 MLLP message (just wrap it)
            hl7_message = self._http_to_mllp(body)
            
            # Log the full message for AI analysis
            if self.logger:
                self.logger.log_hl7_conversion(
                    original_length=len(body),
                    hl7_length=len(hl7_message),
                    hl7_message_start=hl7_message[:100].decode('utf-8', errors='ignore'),
                    full_message=body.decode('utf-8', errors='ignore')
                )
            
            # Send to HL7 server
            hl7_response = self._send_to_hl7_server(hl7_message)
            
            if hl7_response:
                # Log success with full response
                if self.logger:
                    self.logger.log_hl7_response(
                        status="success",
                        response_length=len(hl7_response),
                        hl7_ack=hl7_response[:100],
                        full_response=hl7_response
                    )
                
                # Return HL7 response as HTTP response
                self.send_response(200)
                self.send_header('Content-Type', 'application/hl7-v2')
                self.send_header('X-HL7-Proxy', 'Medaudit-2.0')
                self.send_header('Content-Length', str(len(hl7_response)))
                self.end_headers()
                self.wfile.write(hl7_response.encode('utf-8'))
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
    
    def _http_to_mllp(self, body: bytes) -> bytes:
        """
        Convert HTTP body to MLLP-wrapped message.
        
        Simply wraps the HTTP body in MLLP framing without checking content.
        
        Args:
            body: Request body bytes
            
        Returns:
            MLLP-wrapped message
        """
        # Simply wrap the body in MLLP framing
        return MLLP_START + body + MLLP_END
    
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
                
                # Return raw response without parsing (send directly to client)
                if response:
                    return response.decode('utf-8', errors='ignore')
                
                return None
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"HL7 server connection error: {e}")
            return None


def start_proxy(
    http_host: str = "0.0.0.0",
    http_port: int = 8080,
    hl7_host: str = "localhost",
    hl7_port: int = 2575,
    enable_logging: bool = True,
    log_dir: str = "logs"
):
    """
    Start the HTTP to MLLP converter server.
    
    Clients send HTTP POST requests to this server, which wraps the body
    in MLLP framing and forwards to the target HL7 server.
    
    Args:
        http_host: Host to bind the HTTP server (default: 0.0.0.0 for all interfaces)
        http_port: Port for the HTTP server (default: 8080)
        hl7_host: Target HL7 device/server hostname
        hl7_port: Target HL7 device/server port
        enable_logging: Enable activity logging
        log_dir: Directory for log files
        
    Usage:
        1. Start server: python -m medaudit proxy --port 3000 --hl7-port 2575
        2. Send messages: curl -X POST http://localhost:3000 -d 'MSH|...'
        3. Server wraps in MLLP and forwards to HL7 server
        4. Returns HL7 ACK response
    """
    # Configure the handler
    HL7ProxyHandler.hl7_host = hl7_host
    HL7ProxyHandler.hl7_port = hl7_port
    
    # Setup logging
    if enable_logging:
        HL7ProxyHandler.logger = ProxyLogger(log_dir=log_dir)
    
    # Create and start server
    with socketserver.TCPServer((http_host, http_port), HL7ProxyHandler) as server:
        print(f"HTTP -> MLLP Converter started")
        print(f"  HTTP Server:     http://{http_host}:{http_port}")
        print(f"  Target HL7:      {hl7_host}:{hl7_port}")
        print(f"  Logging:         {'Enabled' if enable_logging else 'Disabled'}")
        print(f"\nSend messages to this server:")
        print(f"  curl -X POST http://localhost:{http_port} -d 'MSH|^~\\&|...'")
        print(f"\nMessages will be wrapped in MLLP and forwarded to {hl7_host}:{hl7_port}")
        print("Press Ctrl+C to stop...")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down converter...")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='HTTP to MLLP Converter - Receives HTTP requests and forwards as MLLP to HL7 server',
        epilog='Example: python -m medaudit.proxy.proxy_server --port 3000 --hl7-port 2575'
    )
    parser.add_argument('--host', default='0.0.0.0', help='Host for the HTTP server (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port for the HTTP server (default: 8080)')
    parser.add_argument('--hl7-host', default='localhost', help='Hostname of the target HL7 server')
    parser.add_argument('--hl7-port', type=int, default=2575, help='Port of the target HL7 server')
    args = parser.parse_args()

    start_proxy(
        http_host=args.host,
        http_port=args.port,
        hl7_host=args.hl7_host,
        hl7_port=args.hl7_port
    )
