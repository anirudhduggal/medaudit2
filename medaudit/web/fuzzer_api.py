"""
HL7 Fuzzer API for Medaudit Web Application.
Provides fuzzing capabilities with YAML/JSON rule support.
"""

import asyncio
import random
import string
import socket
import ssl
import yaml
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Generator
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
import threading
import time

from .database import get_db, Project, FuzzingJob, User
from .auth import require_auth

router = APIRouter(prefix="/api/fuzzer", tags=["fuzzer"])

# MLLP framing
MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'

# Active fuzzing jobs (in-memory tracking)
_active_jobs: Dict[str, dict] = {}
_job_locks: Dict[str, threading.Lock] = {}


# ============== Fuzzing Strategies ==============

class FuzzingStrategies:
    """Collection of fuzzing strategies for HL7 messages."""
    
    @staticmethod
    def mutate_field(value: str, mutation_type: str = "random") -> str:
        """Mutate a field value."""
        mutations = {
            "empty": "",
            "null": "\x00",
            "long": value + "A" * 10000,
            "special": value + "!@#$%^&*(){}[]|\\<>?",
            "unicode": value + "你好世界🔥💀",
            "negative": "-" + value if value.isdigit() else value,
            "float": value + ".99999999",
            "sql": value + "' OR '1'='1",
            "xss": value + "<script>alert(1)</script>",
            "format": value + "%s%s%s%n%n%n",
            "path": value + "/../../../etc/passwd",
            "overflow": "A" * random.randint(1000, 50000),
            "random": ''.join(random.choices(string.printable, k=random.randint(1, 100)))
        }
        return mutations.get(mutation_type, value)
    
    @staticmethod
    def generate_boundary_values(field_type: str = "string") -> List[str]:
        """Generate boundary test values."""
        if field_type == "integer":
            return ["0", "-1", "1", str(2**31 - 1), str(-2**31), str(2**63)]
        elif field_type == "string":
            return ["", "A", "A" * 255, "A" * 256, "A" * 65535, "A" * 65536]
        elif field_type == "date":
            return ["00000000", "99999999", "20001301", "20000100", "20000132", "19000101"]
        else:
            return ["", "0", "-1", "null", "true", "false"]
    
    @staticmethod
    def mutate_delimiter(message: str) -> List[str]:
        """Generate messages with mutated delimiters."""
        mutations = []
        # Replace field separator
        mutations.append(message.replace("|", ";"))
        mutations.append(message.replace("|", "\t"))
        mutations.append(message.replace("|", "||"))
        # Replace component separator
        mutations.append(message.replace("^", "|"))
        mutations.append(message.replace("^", "~"))
        # Replace segment separator
        mutations.append(message.replace("\r", "\n"))
        mutations.append(message.replace("\r", "\r\n"))
        mutations.append(message.replace("\r", ""))
        return mutations
    
    @staticmethod
    def add_segments(base_message: str, segment_types: List[str] = None) -> List[str]:
        """Add extra segments to message."""
        if segment_types is None:
            segment_types = ["NTE", "OBX", "ZXX", "ERR"]
        
        mutations = []
        for seg_type in segment_types:
            # Add at end
            mutations.append(base_message + f"\r{seg_type}|1|Extra segment content")
            # Add multiple
            mutations.append(base_message + "\r".join([f"{seg_type}|{i}|Content {i}" for i in range(100)]))
        return mutations
    
    @staticmethod
    def remove_segments(message: str) -> List[str]:
        """Remove segments from message."""
        segments = message.split("\r")
        mutations = []
        
        # Remove each segment one at a time
        for i in range(len(segments)):
            if i == 0:  # Don't remove MSH completely, but try anyway
                mutations.append("\r".join(segments[1:]))
            else:
                mutations.append("\r".join(segments[:i] + segments[i+1:]))
        
        # Remove all optional segments (keep only MSH)
        mutations.append(segments[0])
        
        return mutations
    
    @staticmethod
    def reorder_segments(message: str) -> List[str]:
        """Reorder segments in message."""
        segments = message.split("\r")
        if len(segments) < 2:
            return [message]
        
        mutations = []
        # Move MSH to end
        mutations.append("\r".join(segments[1:] + [segments[0]]))
        # Reverse order
        mutations.append("\r".join(reversed(segments)))
        # Random shuffle (keeping MSH first)
        for _ in range(3):
            shuffled = segments[1:]
            random.shuffle(shuffled)
            mutations.append(segments[0] + "\r" + "\r".join(shuffled))
        
        return mutations


class FuzzingRule(BaseModel):
    """A single fuzzing rule."""
    name: str
    enabled: bool = True
    target: str  # "field", "segment", "message"
    segment: Optional[str] = None  # e.g., "PID", "MSH"
    field_index: Optional[int] = None  # e.g., 5 for PID-5
    strategy: str  # mutation type
    iterations: int = 10
    values: Optional[List[str]] = None  # custom values


class FuzzingConfig(BaseModel):
    """Fuzzing job configuration."""
    name: str
    target_host: str
    target_port: int = 2575
    use_tls: bool = False
    base_message: str
    rules: List[FuzzingRule]
    delay_ms: int = 100
    timeout_seconds: int = 30
    stop_on_error: bool = False
    max_requests: int = 1000


# Default fuzzing config template
DEFAULT_FUZZING_CONFIG_YAML = """
# Medaudit HL7 Fuzzer Configuration
name: "HL7 Fuzzing Job"
target_host: "localhost"
target_port: 2575
use_tls: false
delay_ms: 100
timeout_seconds: 30
stop_on_error: false
max_requests: 1000

# Base HL7 message to fuzz
base_message: |
  MSH|^~\\&|FUZZER|TEST|TARGET|DEVICE|{timestamp}||ADT^A01|{msg_id}|P|2.5
  PID|1||12345||DOE^JOHN^^^||19800101|M|||123 Main St^^City^ST^12345||555-0100

# Fuzzing rules
rules:
  # Field mutation rules
  - name: "Fuzz Patient ID"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 3
    strategy: "all"  # Try all mutation types
    iterations: 20

  - name: "Fuzz Patient Name"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 5
    strategy: "overflow"
    iterations: 10

  # Boundary testing
  - name: "Date Boundaries"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 7
    strategy: "boundary"
    iterations: 10

  # Custom values
  - name: "SQL Injection Test"
    enabled: true
    target: "field"
    segment: "PID"
    field_index: 3
    strategy: "custom"
    values:
      - "' OR '1'='1"
      - "1; DROP TABLE patients;--"
      - "1 UNION SELECT * FROM users"

  # Segment manipulation
  - name: "Segment Removal"
    enabled: true
    target: "segment"
    strategy: "remove"
    iterations: 5

  - name: "Segment Reordering"
    enabled: true
    target: "segment"
    strategy: "reorder"
    iterations: 5

  # Delimiter fuzzing
  - name: "Delimiter Mutation"
    enabled: true
    target: "message"
    strategy: "delimiter"
    iterations: 10
"""

DEFAULT_FUZZING_CONFIG_JSON = """{
  "name": "HL7 Fuzzing Job",
  "target_host": "localhost",
  "target_port": 2575,
  "use_tls": false,
  "delay_ms": 100,
  "timeout_seconds": 30,
  "stop_on_error": false,
  "max_requests": 1000,
  "base_message": "MSH|^~\\\\&|FUZZER|TEST|TARGET|DEVICE|{timestamp}||ADT^A01|{msg_id}|P|2.5\\rPID|1||12345||DOE^JOHN^^^||19800101|M|||123 Main St^^City^ST^12345||555-0100",
  "rules": [
    {
      "name": "Fuzz Patient ID",
      "enabled": true,
      "target": "field",
      "segment": "PID",
      "field_index": 3,
      "strategy": "all",
      "iterations": 20
    },
    {
      "name": "SQL Injection Test",
      "enabled": true,
      "target": "field",
      "segment": "PID",
      "field_index": 3,
      "strategy": "custom",
      "values": ["' OR '1'='1", "1; DROP TABLE patients;--"]
    }
  ]
}"""


def parse_fuzzing_config(content: str, format: str = "yaml") -> dict:
    """Parse fuzzing configuration from YAML or JSON."""
    try:
        if format.lower() == "yaml":
            return yaml.safe_load(content)
        else:
            return json.loads(content)
    except Exception as e:
        raise ValueError(f"Failed to parse {format} config: {str(e)}")


def generate_fuzzed_messages(base_message: str, rules: List[dict]) -> Generator[Dict[str, Any], None, None]:
    """Generate fuzzed messages based on rules."""
    strategies = FuzzingStrategies()
    
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        
        target = rule.get("target", "field")
        strategy = rule.get("strategy", "random")
        iterations = rule.get("iterations", 10)
        
        if target == "field":
            segment_name = rule.get("segment", "PID")
            field_index = rule.get("field_index", 1)
            
            # Parse message into segments
            segments = base_message.split("\r")
            target_segment_idx = None
            
            for i, seg in enumerate(segments):
                if seg.startswith(segment_name + "|"):
                    target_segment_idx = i
                    break
            
            if target_segment_idx is not None:
                fields = segments[target_segment_idx].split("|")
                
                if strategy == "custom" and rule.get("values"):
                    # Use custom values
                    for value in rule["values"]:
                        if field_index < len(fields):
                            original = fields[field_index]
                            fields[field_index] = value
                            segments[target_segment_idx] = "|".join(fields)
                            yield {
                                "message": "\r".join(segments),
                                "rule": rule["name"],
                                "mutation": f"custom: {value[:50]}",
                                "original_value": original
                            }
                            fields[field_index] = original
                            segments[target_segment_idx] = "|".join(fields)
                
                elif strategy == "boundary":
                    for value in strategies.generate_boundary_values():
                        if field_index < len(fields):
                            original = fields[field_index]
                            fields[field_index] = value
                            segments[target_segment_idx] = "|".join(fields)
                            yield {
                                "message": "\r".join(segments),
                                "rule": rule["name"],
                                "mutation": f"boundary: {value[:50]}",
                                "original_value": original
                            }
                            fields[field_index] = original
                            segments[target_segment_idx] = "|".join(fields)
                
                elif strategy == "all":
                    mutation_types = ["empty", "null", "long", "special", "sql", "format", "overflow"]
                    for mut_type in mutation_types:
                        if field_index < len(fields):
                            original = fields[field_index]
                            fields[field_index] = strategies.mutate_field(original, mut_type)
                            segments[target_segment_idx] = "|".join(fields)
                            yield {
                                "message": "\r".join(segments),
                                "rule": rule["name"],
                                "mutation": f"{mut_type}",
                                "original_value": original
                            }
                            fields[field_index] = original
                            segments[target_segment_idx] = "|".join(fields)
                
                else:
                    for _ in range(iterations):
                        if field_index < len(fields):
                            original = fields[field_index]
                            fields[field_index] = strategies.mutate_field(original, strategy)
                            segments[target_segment_idx] = "|".join(fields)
                            yield {
                                "message": "\r".join(segments),
                                "rule": rule["name"],
                                "mutation": strategy,
                                "original_value": original
                            }
                            fields[field_index] = original
                            segments[target_segment_idx] = "|".join(fields)
        
        elif target == "segment":
            if strategy == "remove":
                for mutated in strategies.remove_segments(base_message):
                    yield {
                        "message": mutated,
                        "rule": rule["name"],
                        "mutation": "segment_removal",
                        "original_value": None
                    }
            
            elif strategy == "reorder":
                for mutated in strategies.reorder_segments(base_message):
                    yield {
                        "message": mutated,
                        "rule": rule["name"],
                        "mutation": "segment_reorder",
                        "original_value": None
                    }
            
            elif strategy == "add":
                for mutated in strategies.add_segments(base_message):
                    yield {
                        "message": mutated,
                        "rule": rule["name"],
                        "mutation": "segment_add",
                        "original_value": None
                    }
        
        elif target == "message":
            if strategy == "delimiter":
                for mutated in strategies.mutate_delimiter(base_message):
                    yield {
                        "message": mutated,
                        "rule": rule["name"],
                        "mutation": "delimiter_mutation",
                        "original_value": None
                    }


def send_hl7_message(host: str, port: int, message: str, use_tls: bool = False, timeout: int = 30) -> Dict[str, Any]:
    """Send an HL7 message and analyze response."""
    try:
        # Replace placeholders
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        msg_id = f"FUZZ{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        message = message.replace("{timestamp}", timestamp).replace("{msg_id}", msg_id)
        
        # Wrap in MLLP
        mllp_message = MLLP_START + message.encode('utf-8', errors='ignore') + MLLP_END
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        start_time = time.time()
        sock.connect((host, port))
        sock.sendall(mllp_message)
        
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
        
        # Analyze response for interesting findings
        is_interesting = False
        finding_type = None
        
        # Check for error indicators
        if not response_text:
            is_interesting = True
            finding_type = "no_response"
        elif "MSA|AE" in response_text or "MSA|AR" in response_text:
            is_interesting = True
            finding_type = "application_error"
        elif "ERR|" in response_text:
            is_interesting = True
            finding_type = "error_segment"
        elif len(response_text) > 10000:
            is_interesting = True
            finding_type = "large_response"
        elif (end_time - start_time) > 5:
            is_interesting = True
            finding_type = "slow_response"
        
        return {
            "success": True,
            "response": response_text[:1000],
            "response_length": len(response_text),
            "response_time_ms": int((end_time - start_time) * 1000),
            "is_interesting": is_interesting,
            "finding_type": finding_type
        }
        
    except socket.timeout:
        return {
            "success": False,
            "error": "timeout",
            "is_interesting": True,
            "finding_type": "timeout"
        }
    except ConnectionRefusedError:
        return {
            "success": False,
            "error": "connection_refused",
            "is_interesting": True,
            "finding_type": "connection_refused"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "is_interesting": True,
            "finding_type": "exception"
        }


def run_fuzzing_job(job_id: str, config: dict, db_session_factory):
    """Run a fuzzing job in background."""
    global _active_jobs
    
    _active_jobs[job_id] = {
        "status": "running",
        "progress": 0,
        "total_requests": 0,
        "successful": 0,
        "errors": 0,
        "interesting": 0,
        "findings": [],
        "should_stop": False
    }
    
    try:
        db = db_session_factory()
        job = db.query(FuzzingJob).filter(FuzzingJob.id == job_id).first()
        if not job:
            return
        
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()
        
        # Generate fuzzed messages
        base_message = config.get("base_message", "")
        rules = config.get("rules", [])
        delay_ms = config.get("delay_ms", 100)
        max_requests = config.get("max_requests", 1000)
        stop_on_error = config.get("stop_on_error", False)
        
        messages = list(generate_fuzzed_messages(base_message, rules))
        total = min(len(messages), max_requests)
        
        findings = []
        
        for i, msg_data in enumerate(messages[:max_requests]):
            if _active_jobs.get(job_id, {}).get("should_stop"):
                break
            
            # Send message
            result = send_hl7_message(
                host=config.get("target_host", "localhost"),
                port=config.get("target_port", 2575),
                message=msg_data["message"],
                use_tls=config.get("use_tls", False),
                timeout=config.get("timeout_seconds", 30)
            )
            
            _active_jobs[job_id]["total_requests"] += 1
            _active_jobs[job_id]["progress"] = int((i + 1) / total * 100)
            
            if result.get("success"):
                _active_jobs[job_id]["successful"] += 1
            else:
                _active_jobs[job_id]["errors"] += 1
                if stop_on_error:
                    break
            
            if result.get("is_interesting"):
                _active_jobs[job_id]["interesting"] += 1
                finding = {
                    "index": i,
                    "rule": msg_data["rule"],
                    "mutation": msg_data["mutation"],
                    "finding_type": result.get("finding_type"),
                    "response_time_ms": result.get("response_time_ms"),
                    "message_preview": msg_data["message"][:200],
                    "response_preview": result.get("response", "")[:200],
                    "error": result.get("error")
                }
                findings.append(finding)
                _active_jobs[job_id]["findings"].append(finding)
            
            time.sleep(delay_ms / 1000)
        
        # Update job in database
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        job.progress = 100
        job.total_requests = _active_jobs[job_id]["total_requests"]
        job.successful_requests = _active_jobs[job_id]["successful"]
        job.error_requests = _active_jobs[job_id]["errors"]
        job.interesting_findings = _active_jobs[job_id]["interesting"]
        job.findings = findings
        db.commit()
        
        _active_jobs[job_id]["status"] = "completed"
        
    except Exception as e:
        _active_jobs[job_id]["status"] = "error"
        _active_jobs[job_id]["error"] = str(e)
        
        try:
            db = db_session_factory()
            job = db.query(FuzzingJob).filter(FuzzingJob.id == job_id).first()
            if job:
                job.status = "error"
                db.commit()
        except:
            pass
    finally:
        try:
            db.close()
        except:
            pass


@router.get("/templates")
async def get_fuzzing_templates(user: User = Depends(require_auth)):
    """Get default fuzzing configuration templates."""
    return {
        "yaml": DEFAULT_FUZZING_CONFIG_YAML,
        "json": DEFAULT_FUZZING_CONFIG_JSON
    }


@router.post("/validate")
async def validate_config(
    config_content: str,
    config_format: str = "yaml",
    user: User = Depends(require_auth)
):
    """Validate a fuzzing configuration."""
    try:
        config = parse_fuzzing_config(config_content, config_format)
        
        # Check required fields
        required = ["target_host", "base_message", "rules"]
        missing = [f for f in required if f not in config]
        
        if missing:
            return {
                "valid": False,
                "error": f"Missing required fields: {', '.join(missing)}"
            }
        
        return {
            "valid": True,
            "config": config,
            "rule_count": len(config.get("rules", []))
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


@router.post("/projects/{project_id}/jobs")
async def create_fuzzing_job(
    project_id: str,
    name: str,
    config_content: str,
    config_format: str = "yaml",
    background_tasks: BackgroundTasks = None,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Create and start a new fuzzing job."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Parse config
    try:
        config = parse_fuzzing_config(config_content, config_format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Create job
    job = FuzzingJob(
        project_id=project_id,
        name=name,
        target_host=config.get("target_host", "localhost"),
        target_port=config.get("target_port", 2575),
        use_tls=config.get("use_tls", False),
        config_format=config_format,
        config_content=config_content,
        status="pending"
    )
    
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Start fuzzing in background
    from .database import get_db_manager
    db_manager = get_db_manager()
    
    thread = threading.Thread(
        target=run_fuzzing_job,
        args=(job.id, config, db_manager.SessionLocal)
    )
    thread.daemon = True
    thread.start()
    
    return {"success": True, "job": job.to_dict()}


@router.get("/projects/{project_id}/jobs")
async def list_fuzzing_jobs(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List fuzzing jobs for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"jobs": [j.to_dict() for j in project.fuzzing_jobs]}


@router.get("/projects/{project_id}/jobs/{job_id}")
async def get_fuzzing_job(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get details of a fuzzing job."""
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get real-time status if running
    live_status = _active_jobs.get(job_id, {})
    
    result = job.to_dict()
    result["config_content"] = job.config_content
    result["findings"] = job.findings or live_status.get("findings", [])
    
    if live_status:
        result["live_progress"] = live_status.get("progress", job.progress)
        result["live_total_requests"] = live_status.get("total_requests", job.total_requests)
        result["live_status"] = live_status.get("status", job.status)
    
    return {"job": result}


@router.post("/projects/{project_id}/jobs/{job_id}/stop")
async def stop_fuzzing_job(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Stop a running fuzzing job."""
    if job_id in _active_jobs:
        _active_jobs[job_id]["should_stop"] = True
    
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if job:
        job.status = "stopped"
        db.commit()
    
    return {"success": True}


@router.delete("/projects/{project_id}/jobs/{job_id}")
async def delete_fuzzing_job(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Delete a fuzzing job."""
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Stop if running
    if job_id in _active_jobs:
        _active_jobs[job_id]["should_stop"] = True
    
    db.delete(job)
    db.commit()
    
    return {"success": True}
