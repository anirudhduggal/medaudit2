# Medaudit HL7 Fuzzer - Protocol Handling
# HL7/MLLP communication for medical device fuzzing

"""
HL7/MLLP Protocol Handling

This module provides protocol-level handling for HL7 messages over MLLP
(Minimal Lower Layer Protocol). It handles message framing, transmission,
and response analysis for fuzzing operations.

MLLP Framing:
- Start Block: 0x0B (VT - Vertical Tab)
- End Block: 0x1C 0x0D (FS + CR)

The module includes timeout handling, TLS support, and response analysis
to detect interesting behaviors during fuzzing.
"""

import socket
import ssl
import time
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# MLLP (Minimal Lower Layer Protocol) framing characters
MLLP_START = b'\x0b'  # VT - Vertical Tab (Start Block)
MLLP_END = b'\x1c\x0d'  # FS + CR (End Block)


def wrap_mllp(message: str) -> bytes:
    """
    Wrap an HL7 message in MLLP framing.
    
    Args:
        message: HL7 message string
        
    Returns:
        MLLP-framed message bytes
        
    Example:
        >>> wrapped = wrap_mllp("MSH|^~\\\\&|...")
        >>> wrapped.startswith(b'\\x0b')
        True
    """
    return MLLP_START + message.encode('utf-8', errors='ignore') + MLLP_END


def unwrap_mllp(data: bytes) -> str:
    """
    Remove MLLP framing from received data.
    
    Args:
        data: Raw bytes received from socket
        
    Returns:
        Decoded HL7 message string
        
    Example:
        >>> unwrap_mllp(b'\\x0bMSH|...\\x1c\\r')
        'MSH|...'
    """
    if data.startswith(MLLP_START):
        data = data[1:]
    
    end_idx = data.find(MLLP_END)
    if end_idx > 0:
        data = data[:end_idx]
    else:
        # Try just FS without CR
        end_idx = data.find(b'\x1c')
        if end_idx > 0:
            data = data[:end_idx]
    
    return data.decode('utf-8', errors='ignore')


def send_hl7_message(
    host: str,
    port: int,
    message: str,
    use_tls: bool = False,
    timeout: int = 30,
    replace_placeholders: bool = True
) -> Dict[str, Any]:
    """
    Send an HL7 message over MLLP and analyze the response.
    
    This function handles the complete send/receive cycle for HL7 messages,
    including MLLP framing, TLS encryption, and response analysis for
    interesting security findings.
    
    Args:
        host: Target hostname or IP address
        port: Target port (typically 2575 for HL7)
        message: HL7 message to send
        use_tls: Whether to use TLS encryption
        timeout: Socket timeout in seconds
        replace_placeholders: Replace {timestamp} and {msg_id} placeholders
        
    Returns:
        Dictionary containing:
        - success: Whether the request completed
        - response: Response message text (truncated to 1000 chars)
        - response_length: Full response length
        - response_time_ms: Round-trip time in milliseconds
        - is_interesting: Whether this might be a security finding
        - finding_type: Type of interesting behavior detected
        - error: Error message if failed
        
    Example:
        >>> result = send_hl7_message("localhost", 2575, "MSH|^~\\\\&|...")
        >>> if result["success"]:
        ...     print(f"Response time: {result['response_time_ms']}ms")
        
    Finding Types:
        - no_response: Server didn't respond
        - application_error: MSA|AE or MSA|AR received
        - error_segment: ERR| segment in response
        - large_response: Response > 10KB
        - slow_response: Response time > 5s
        - timeout: Socket timeout occurred
        - connection_refused: Connection was refused
        - exception: Other error occurred
    """
    sock = None
    
    try:
        # Replace placeholders in message
        if replace_placeholders:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            msg_id = f"FUZZ{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            message = message.replace("{timestamp}", timestamp).replace("{msg_id}", msg_id)
        
        # Create and configure socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Apply TLS if requested
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # Connect and send
        start_time = time.time()
        sock.connect((host, port))
        
        mllp_message = wrap_mllp(message)
        sock.sendall(mllp_message)
        
        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if MLLP_END in response:
                    break
            except socket.timeout:
                break
        
        end_time = time.time()
        response_time_ms = int((end_time - start_time) * 1000)
        
        # Parse response
        response_text = unwrap_mllp(response) if response else ""
        
        # Analyze response for interesting findings
        is_interesting, finding_type = analyze_response(
            response_text, 
            response_time_ms
        )
        
        return {
            "success": True,
            "response": response_text[:1000],
            "response_length": len(response_text),
            "response_time_ms": response_time_ms,
            "is_interesting": is_interesting,
            "finding_type": finding_type
        }
        
    except socket.timeout:
        logger.debug(f"Timeout connecting to {host}:{port}")
        return {
            "success": False,
            "error": "timeout",
            "is_interesting": True,
            "finding_type": "timeout"
        }
    except ConnectionRefusedError:
        logger.debug(f"Connection refused by {host}:{port}")
        return {
            "success": False,
            "error": "connection_refused",
            "is_interesting": True,
            "finding_type": "connection_refused"
        }
    except ConnectionResetError:
        logger.debug(f"Connection reset by {host}:{port}")
        return {
            "success": False,
            "error": "connection_reset",
            "is_interesting": True,
            "finding_type": "connection_reset"
        }
    except Exception as e:
        logger.error(f"Error sending HL7 message: {e}")
        return {
            "success": False,
            "error": str(e),
            "is_interesting": True,
            "finding_type": "exception"
        }
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def analyze_response(
    response_text: str, 
    response_time_ms: int
) -> tuple:
    """
    Analyze an HL7 response for interesting security findings.
    
    Args:
        response_text: Decoded response message
        response_time_ms: Response time in milliseconds
        
    Returns:
        Tuple of (is_interesting: bool, finding_type: str or None)
        
    Example:
        >>> is_int, ftype = analyze_response("MSH|...|\\rMSA|AE|...", 100)
        >>> is_int
        True
        >>> ftype
        'application_error'
    """
    is_interesting = False
    finding_type = None
    
    # Check for various interesting conditions
    if not response_text:
        is_interesting = True
        finding_type = "no_response"
    elif "MSA|AE" in response_text or "MSA|AR" in response_text:
        # Application error or rejection
        is_interesting = True
        finding_type = "application_error"
    elif "ERR|" in response_text:
        # Error segment present
        is_interesting = True
        finding_type = "error_segment"
    elif len(response_text) > 10000:
        # Unusually large response
        is_interesting = True
        finding_type = "large_response"
    elif response_time_ms > 5000:
        # Slow response (potential DoS indicator)
        is_interesting = True
        finding_type = "slow_response"
    elif "Exception" in response_text or "Error" in response_text:
        # Error message leaked
        is_interesting = True
        finding_type = "error_disclosure"
    elif "SELECT" in response_text.upper() or "INSERT" in response_text.upper():
        # SQL keywords in response (potential SQLi)
        is_interesting = True
        finding_type = "sql_disclosure"
    
    return is_interesting, finding_type


def test_connection(host: str, port: int, use_tls: bool = False, timeout: int = 5) -> Dict[str, Any]:
    """
    Test connectivity to an HL7 server.
    
    Args:
        host: Target hostname
        port: Target port
        use_tls: Whether to use TLS
        timeout: Connection timeout
        
    Returns:
        Dictionary with connection status and details
        
    Example:
        >>> result = test_connection("localhost", 2575)
        >>> print(result["connected"])
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        start = time.time()
        sock.connect((host, port))
        latency_ms = int((time.time() - start) * 1000)
        sock.close()
        
        return {
            "connected": True,
            "host": host,
            "port": port,
            "tls": use_tls,
            "latency_ms": latency_ms
        }
    except Exception as e:
        return {
            "connected": False,
            "host": host,
            "port": port,
            "tls": use_tls,
            "error": str(e)
        }
