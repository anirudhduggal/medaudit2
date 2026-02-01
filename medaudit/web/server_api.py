"""
Server Management API for Medaudit Web Application.
Provides multi-server configuration, TLS support, and message logging.
"""

import socket
import ssl
import threading
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db, Project, ServerInstance, User
from .auth import require_auth

router = APIRouter(prefix="/api/server", tags=["server"])

# Active server processes
_active_servers: Dict[str, dict] = {}

# MLLP framing
MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'


class ServerCreate(BaseModel):
    """Schema for creating a server instance."""
    name: str
    host: str = "0.0.0.0"
    port: int = 2575
    use_tls: bool = False
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class ServerUpdate(BaseModel):
    """Schema for updating a server instance."""
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    use_tls: Optional[bool] = None
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class ManagedHL7Server:
    """HL7 Server that can be managed through the web interface."""
    
    def __init__(self, server_id: str, host: str, port: int, 
                 use_tls: bool = False, cert_path: str = None, key_path: str = None,
                 db_session_factory=None):
        self.server_id = server_id
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cert_path = cert_path
        self.key_path = key_path
        self.db_session_factory = db_session_factory
        
        self.server_socket = None
        self.running = False
        self.connections = 0
        self.messages = 0
        self.message_log = []
        self._lock = threading.Lock()
    
    def _generate_ack(self, hl7_message: str) -> str:
        """Generate HL7 ACK response."""
        try:
            segments = hl7_message.split('\r')
            msh_segment = segments[0]
            msh_fields = msh_segment.split('|')
            
            message_id = msh_fields[9] if len(msh_fields) > 9 else "UNKNOWN"
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            
            ack = (
                f"MSH|^~\\&|MEDAUDIT_SERVER|MOCK|TEST|TEST|{timestamp}||ACK|{message_id}|P|2.5\r"
                f"MSA|AA|{message_id}|Message received successfully"
            )
            return ack
        except Exception:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            return f"MSH|^~\\&|MEDAUDIT_SERVER|MOCK|TEST|TEST|{timestamp}||ACK|UNKNOWN|P|2.5\rMSA|AA|UNKNOWN|Error generating ACK"
    
    def _parse_hl7_message(self, message: str) -> dict:
        """Parse HL7 message for logging."""
        try:
            segments = message.split('\r')
            msh = segments[0].split('|')
            
            return {
                "message_type": msh[8] if len(msh) > 8 else "Unknown",
                "message_id": msh[9] if len(msh) > 9 else "Unknown",
                "sending_app": msh[2] if len(msh) > 2 else "Unknown",
                "segment_count": len(segments),
                "message_preview": message[:500]
            }
        except Exception:
            return {
                "message_type": "Unknown",
                "message_id": "Unknown",
                "sending_app": "Unknown",
                "segment_count": 0,
                "message_preview": message[:500]
            }
    
    def _log_event(self, event_type: str, data: dict):
        """Log an event."""
        with self._lock:
            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "data": data
            }
            self.message_log.append(event)
            
            # Keep last 1000 events
            if len(self.message_log) > 1000:
                self.message_log = self.message_log[-1000:]
            
            # Update database
            if self.db_session_factory:
                try:
                    db = self.db_session_factory()
                    server = db.query(ServerInstance).filter(
                        ServerInstance.id == self.server_id
                    ).first()
                    if server:
                        server.message_log = self.message_log
                        server.total_connections = self.connections
                        server.total_messages = self.messages
                        db.commit()
                    db.close()
                except Exception:
                    pass
    
    def _handle_client(self, client_socket, client_address):
        """Handle a single client connection."""
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.connections += 1
        
        self._log_event("connection", {
            "client": client_id,
            "action": "connected"
        })
        
        buffer = b""
        
        try:
            client_socket.settimeout(300)  # 5 minute timeout
            
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    buffer += data
                    
                    # Process complete MLLP frames
                    while MLLP_START in buffer and MLLP_END in buffer:
                        start_idx = buffer.find(MLLP_START)
                        end_idx = buffer.find(MLLP_END)
                        
                        if end_idx < start_idx:
                            buffer = buffer[start_idx:]
                            continue
                        
                        # Extract message
                        mllp_frame = buffer[start_idx:end_idx + 2]
                        buffer = buffer[end_idx + 2:]
                        
                        # Parse MLLP
                        hl7_message = mllp_frame[1:].decode('utf-8', errors='ignore')
                        if hl7_message.endswith('\x1c\r'):
                            hl7_message = hl7_message[:-2]
                        
                        self.messages += 1
                        
                        # Log received message
                        msg_info = self._parse_hl7_message(hl7_message)
                        self._log_event("message_received", {
                            "client": client_id,
                            "message_number": self.messages,
                            **msg_info
                        })
                        
                        # Generate and send ACK
                        ack = self._generate_ack(hl7_message)
                        mllp_ack = MLLP_START + ack.encode('utf-8') + MLLP_END
                        
                        try:
                            client_socket.sendall(mllp_ack)
                            self._log_event("message_sent", {
                                "client": client_id,
                                "type": "ACK",
                                "message_id": msg_info.get("message_id")
                            })
                        except Exception as e:
                            self._log_event("error", {
                                "client": client_id,
                                "error": f"Failed to send ACK: {str(e)}"
                            })
                
                except socket.timeout:
                    continue
                except Exception as e:
                    self._log_event("error", {
                        "client": client_id,
                        "error": str(e)
                    })
                    break
        
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            self._log_event("connection", {
                "client": client_id,
                "action": "disconnected"
            })
    
    def start(self):
        """Start the server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1.0)  # For checking stop condition
            
            self.running = True
            
            self._log_event("server", {
                "action": "started",
                "host": self.host,
                "port": self.port,
                "tls": self.use_tls
            })
            
            # Accept connections loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    if self.use_tls and self.cert_path and self.key_path:
                        try:
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            context.load_cert_chain(self.cert_path, self.key_path)
                            client_socket = context.wrap_socket(client_socket, server_side=True)
                        except Exception as e:
                            self._log_event("error", {
                                "error": f"TLS handshake failed: {str(e)}"
                            })
                            client_socket.close()
                            continue
                    
                    # Handle client in thread
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
                        self._log_event("error", {
                            "error": f"Accept error: {str(e)}"
                        })
        
        except Exception as e:
            self._log_event("error", {
                "action": "start_failed",
                "error": str(e)
            })
            raise
        
        finally:
            self._log_event("server", {
                "action": "stopped"
            })
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.server_socket = None


def run_server(server_id: str, config: dict, db_session_factory):
    """Run a server in a background thread."""
    global _active_servers
    
    try:
        server = ManagedHL7Server(
            server_id=server_id,
            host=config.get("host", "0.0.0.0"),
            port=config.get("port", 2575),
            use_tls=config.get("use_tls", False),
            cert_path=config.get("cert_path"),
            key_path=config.get("key_path"),
            db_session_factory=db_session_factory
        )
        
        _active_servers[server_id] = {
            "server": server,
            "status": "running",
            "started_at": datetime.now().isoformat()
        }
        
        # Update database
        db = db_session_factory()
        db_server = db.query(ServerInstance).filter(ServerInstance.id == server_id).first()
        if db_server:
            db_server.status = "running"
            db_server.started_at = datetime.utcnow()
            db.commit()
        db.close()
        
        server.start()
        
    except Exception as e:
        _active_servers[server_id] = {
            "status": "error",
            "error": str(e)
        }
        
        # Update database
        try:
            db = db_session_factory()
            db_server = db.query(ServerInstance).filter(ServerInstance.id == server_id).first()
            if db_server:
                db_server.status = "error"
                db.commit()
            db.close()
        except:
            pass
    
    finally:
        if server_id in _active_servers:
            _active_servers[server_id]["status"] = "stopped"


@router.post("/projects/{project_id}/servers")
async def create_server(
    project_id: str,
    server_data: ServerCreate,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Create a new server instance."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if port is already in use by another server in this project
    existing = db.query(ServerInstance).filter(
        ServerInstance.project_id == project_id,
        ServerInstance.port == server_data.port,
        ServerInstance.status == "running"
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Port {server_data.port} is already in use by another server"
        )
    
    server = ServerInstance(
        project_id=project_id,
        name=server_data.name,
        host=server_data.host,
        port=server_data.port,
        use_tls=server_data.use_tls,
        cert_path=server_data.cert_path,
        key_path=server_data.key_path
    )
    
    db.add(server)
    db.commit()
    db.refresh(server)
    
    return {"success": True, "server": server.to_dict()}


@router.get("/projects/{project_id}/servers")
async def list_servers(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List all server instances for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    servers = []
    for s in project.server_instances:
        server_dict = s.to_dict()
        
        # Add live status
        if s.id in _active_servers:
            live = _active_servers[s.id]
            server_dict["live_status"] = live.get("status", "unknown")
            if "server" in live:
                server_dict["live_connections"] = live["server"].connections
                server_dict["live_messages"] = live["server"].messages
        
        servers.append(server_dict)
    
    return {"servers": servers}


@router.get("/projects/{project_id}/servers/{server_id}")
async def get_server(
    project_id: str,
    server_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get a specific server instance."""
    server = db.query(ServerInstance).filter(
        ServerInstance.id == server_id,
        ServerInstance.project_id == project_id
    ).first()
    
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    result = server.to_dict()
    
    # Add live status and logs
    if server_id in _active_servers:
        live = _active_servers[server_id]
        result["live_status"] = live.get("status", "unknown")
        if "server" in live:
            result["live_connections"] = live["server"].connections
            result["live_messages"] = live["server"].messages
            result["message_log"] = live["server"].message_log[-100:]  # Last 100 events
    else:
        result["message_log"] = server.message_log[-100:] if server.message_log else []
    
    return {"server": result}


@router.put("/projects/{project_id}/servers/{server_id}")
async def update_server(
    project_id: str,
    server_id: str,
    server_data: ServerUpdate,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Update a server instance (only when stopped)."""
    server = db.query(ServerInstance).filter(
        ServerInstance.id == server_id,
        ServerInstance.project_id == project_id
    ).first()
    
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if server is running
    if server_id in _active_servers and _active_servers[server_id].get("status") == "running":
        raise HTTPException(
            status_code=400,
            detail="Cannot update a running server. Stop it first."
        )
    
    # Update fields
    if server_data.name is not None:
        server.name = server_data.name
    if server_data.host is not None:
        server.host = server_data.host
    if server_data.port is not None:
        server.port = server_data.port
    if server_data.use_tls is not None:
        server.use_tls = server_data.use_tls
    if server_data.cert_path is not None:
        server.cert_path = server_data.cert_path
    if server_data.key_path is not None:
        server.key_path = server_data.key_path
    
    db.commit()
    db.refresh(server)
    
    return {"success": True, "server": server.to_dict()}


@router.post("/projects/{project_id}/servers/{server_id}/start")
async def start_server(
    project_id: str,
    server_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Start a server instance."""
    server = db.query(ServerInstance).filter(
        ServerInstance.id == server_id,
        ServerInstance.project_id == project_id
    ).first()
    
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if already running
    if server_id in _active_servers and _active_servers[server_id].get("status") == "running":
        raise HTTPException(status_code=400, detail="Server is already running")
    
    # Check TLS requirements
    if server.use_tls and (not server.cert_path or not server.key_path):
        raise HTTPException(
            status_code=400,
            detail="TLS enabled but certificate/key paths not configured"
        )
    
    # Start server in background thread
    from .database import get_db_manager
    db_manager = get_db_manager()
    
    config = {
        "host": server.host,
        "port": server.port,
        "use_tls": server.use_tls,
        "cert_path": server.cert_path,
        "key_path": server.key_path
    }
    
    thread = threading.Thread(
        target=run_server,
        args=(server_id, config, db_manager.SessionLocal),
        daemon=True
    )
    thread.start()
    
    # Wait briefly to check if started successfully
    import time
    time.sleep(0.5)
    
    if server_id in _active_servers:
        status = _active_servers[server_id].get("status")
        if status == "error":
            error = _active_servers[server_id].get("error", "Unknown error")
            raise HTTPException(status_code=500, detail=f"Failed to start server: {error}")
    
    return {"success": True, "status": "starting"}


@router.post("/projects/{project_id}/servers/{server_id}/stop")
async def stop_server(
    project_id: str,
    server_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Stop a server instance."""
    server = db.query(ServerInstance).filter(
        ServerInstance.id == server_id,
        ServerInstance.project_id == project_id
    ).first()
    
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Stop server
    if server_id in _active_servers and "server" in _active_servers[server_id]:
        _active_servers[server_id]["server"].stop()
    
    # Update database
    server.status = "stopped"
    db.commit()
    
    return {"success": True}


@router.delete("/projects/{project_id}/servers/{server_id}")
async def delete_server(
    project_id: str,
    server_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Delete a server instance."""
    server = db.query(ServerInstance).filter(
        ServerInstance.id == server_id,
        ServerInstance.project_id == project_id
    ).first()
    
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Stop if running
    if server_id in _active_servers and "server" in _active_servers[server_id]:
        _active_servers[server_id]["server"].stop()
    
    db.delete(server)
    db.commit()
    
    return {"success": True}


@router.get("/projects/{project_id}/servers/{server_id}/logs")
async def get_server_logs(
    project_id: str,
    server_id: str,
    limit: int = 100,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get message logs for a server."""
    server = db.query(ServerInstance).filter(
        ServerInstance.id == server_id,
        ServerInstance.project_id == project_id
    ).first()
    
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get live logs if running, otherwise from database
    if server_id in _active_servers and "server" in _active_servers[server_id]:
        logs = _active_servers[server_id]["server"].message_log[-limit:]
    else:
        logs = (server.message_log or [])[-limit:]
    
    return {
        "server_id": server_id,
        "logs": logs,
        "total": len(logs)
    }
