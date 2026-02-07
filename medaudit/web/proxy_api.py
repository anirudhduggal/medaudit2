"""
Proxy Management API for Medaudit Web UI
Manages HTTP→HL7 proxy instances
"""

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel
import subprocess
import signal
import psutil
import logging
from .database import get_db, User
from .auth import require_auth


logger = logging.getLogger(__name__)
router = APIRouter()

# Active proxy processes (in-memory)
active_proxies = {}


class ProxyStartRequest(BaseModel):
    proxy_port: int
    hl7_host: str = "localhost"
    hl7_port: int = 2575


class ProxyStopRequest(BaseModel):
    proxy_port: int


@router.post("/api/proxy/start")
async def start_proxy(
    request: ProxyStartRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Start an HTTP→HL7 proxy instance."""
    try:
        proxy_port = request.proxy_port
        hl7_host = request.hl7_host
        hl7_port = request.hl7_port
        
        logger.info(f"Starting proxy on port {proxy_port} -> {hl7_host}:{hl7_port}")
        logger.info(f"Current active_proxies: {list(active_proxies.keys())}")
        
        # First, check if port is actually in use by checking socket
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        connect_result = sock.connect_ex(('127.0.0.1', proxy_port))
        port_in_use = connect_result == 0
        sock.close()
        
        logger.info(f"Port {proxy_port} check: connect_result={connect_result}, port_in_use={port_in_use}")
        
        # If port is in use, check if it's our tracked process
        if port_in_use:
            if proxy_port in active_proxies:
                proc = active_proxies[proxy_port]
                poll_result = proc.poll()
                logger.info(f"Tracked process poll result: {poll_result}")
                if poll_result is None:
                    # Our process is still running
                    return {
                        "success": False,
                        "detail": f"Proxy already running on port {proxy_port}"
                    }
                else:
                    # Process died, clean it up
                    del active_proxies[proxy_port]
            # Port in use by something else
            return {
                "success": False,
                "detail": f"Port {proxy_port} is already in use by another process"
            }
        
        # Port is free - clean up any stale tracking
        if proxy_port in active_proxies:
            logger.info(f"Cleaning up stale tracking for port {proxy_port}")
            del active_proxies[proxy_port]
        
        # Start proxy process
        process = subprocess.Popen(
            [
                "python3", "-m", "medaudit.proxy.proxy_server",
                "--host", "0.0.0.0",
                "--port", str(proxy_port),
                "--hl7-host", hl7_host,
                "--hl7-port", str(hl7_port)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Store process
        active_proxies[proxy_port] = process
        
        logger.info(f"Proxy started successfully on port {proxy_port}, PID: {process.pid}")
        
        return {
            "success": True,
            "proxy": {
                "port": proxy_port,
                "hl7_host": hl7_host,
                "hl7_port": hl7_port,
                "pid": process.pid,
                "status": "running"
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to start proxy: {e}", exc_info=True)
        return {
            "success": False,
            "detail": str(e)
        }


@router.post("/api/proxy/stop")
async def stop_proxy(
    request: ProxyStopRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Stop a running proxy instance."""
    try:
        proxy_port = request.proxy_port
        if proxy_port not in active_proxies:
            return {
                "success": False,
                "detail": f"No proxy running on port {proxy_port}"
            }
        
        process = active_proxies[proxy_port]
        
        # Try graceful termination first
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force kill if it doesn't stop
            process.kill()
            process.wait()
        
        del active_proxies[proxy_port]
        
        return {
            "success": True,
            "message": f"Proxy on port {proxy_port} stopped"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/proxy/status")
async def get_proxy_status(
    proxy_port: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get status of a proxy instance."""
    try:
        if proxy_port not in active_proxies:
            return {
                "success": True,
                "proxy": {
                    "port": proxy_port,
                    "status": "stopped"
                }
            }
        
        process = active_proxies[proxy_port]
        
        # Check if process is still alive
        if process.poll() is not None:
            # Process died
            del active_proxies[proxy_port]
            return {
                "success": True,
                "proxy": {
                    "port": proxy_port,
                    "status": "stopped",
                    "exit_code": process.returncode
                }
            }
        
        # Get process info
        try:
            proc = psutil.Process(process.pid)
            cpu_percent = proc.cpu_percent(interval=0.1)
            memory_mb = proc.memory_info().rss / 1024 / 1024
        except:
            cpu_percent = 0
            memory_mb = 0
        
        return {
            "success": True,
            "proxy": {
                "port": proxy_port,
                "pid": process.pid,
                "status": "running",
                "cpu_percent": cpu_percent,
                "memory_mb": round(memory_mb, 2)
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/proxy/list")
async def list_proxies(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List all active proxy instances."""
    try:
        proxies = []
        
        # Clean up dead processes
        dead_ports = []
        for port, process in active_proxies.items():
            if process.poll() is not None:
                dead_ports.append(port)
            else:
                proxies.append({
                    "port": port,
                    "pid": process.pid,
                    "status": "running"
                })
        
        for port in dead_ports:
            del active_proxies[port]
        
        return {
            "success": True,
            "proxies": proxies
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
