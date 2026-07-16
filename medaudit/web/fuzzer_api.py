# Medaudit Web - Fuzzer API
# Web API endpoints for the HL7 fuzzer

"""
HL7 Fuzzer Web API

This module provides FastAPI endpoints for the fuzzer functionality.
Core fuzzing logic is imported from the dedicated fuzzer module.

Endpoints:
- GET /api/fuzzer/templates - Get fuzzing config templates
- POST /api/fuzzer/validate - Validate a fuzzing config
- POST /api/fuzzer/projects/{id}/jobs - Create a fuzzing job
- GET /api/fuzzer/projects/{id}/jobs - List fuzzing jobs
- GET /api/fuzzer/projects/{id}/jobs/{jid} - Get job details
- POST /api/fuzzer/projects/{id}/jobs/{jid}/stop - Stop a job
- DELETE /api/fuzzer/projects/{id}/jobs/{jid} - Delete a job
"""

import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db, Project, FuzzingJob, User
from .auth import require_auth

# Import from dedicated fuzzer module
from medaudit.fuzzer import (
    FuzzingStrategies,
    FuzzingRule,
    FuzzingConfig,
    parse_fuzzing_config,
    generate_fuzzed_messages,
    run_fuzzing_job,
    send_hl7_message,
    MLLP_START,
    MLLP_END,
    DEFAULT_FUZZING_CONFIG_YAML,
    DEFAULT_FUZZING_CONFIG_JSON,
)
from medaudit.fuzzer.engine import (
    _active_jobs,
    stop_job as engine_stop_job,
    get_job_status,
    validate_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fuzzer", tags=["fuzzer"])


@router.get("/templates")
async def get_fuzzing_templates(user: User = Depends(require_auth)):
    """
    Get default fuzzing configuration templates.
    
    Returns:
        Dictionary with 'yaml' and 'json' template strings
    """
    return {
        "yaml": DEFAULT_FUZZING_CONFIG_YAML,
        "json": DEFAULT_FUZZING_CONFIG_JSON
    }


@router.post("/validate")
async def validate_fuzzing_config(
    config_content: str,
    config_format: str = "yaml",
    user: User = Depends(require_auth)
):
    """
    Validate a fuzzing configuration.
    
    Args:
        config_content: Configuration string (YAML or JSON)
        config_format: Format type ('yaml' or 'json')
        
    Returns:
        Validation result with parsed config if valid
    """
    try:
        config = parse_fuzzing_config(config_content, config_format)
        
        # Use the validation from engine
        is_valid, errors = validate_config(config)
        
        if not is_valid:
            return {
                "valid": False,
                "errors": errors
            }
        
        return {
            "valid": True,
            "config": config,
            "rule_count": len(config.get("rules", []))
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


class CreateFuzzingJobRequest(BaseModel):
    """Request body for creating a fuzzing job."""
    name: str
    config_content: str
    config_format: str = "yaml"
    # Operator confirmation required to fuzz a non-loopback (remote) target.
    confirm_target: bool = False


@router.post("/projects/{project_id}/jobs")
async def create_fuzzing_job(
    project_id: str,
    request: CreateFuzzingJobRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Create and start a new fuzzing job.
    
    Args:
        project_id: Project to attach the job to
        name: Job name
        config_content: Fuzzing configuration (YAML/JSON)
        config_format: Configuration format
        
    Returns:
        Created job details
    """
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Parse config
    try:
        config = parse_fuzzing_config(request.config_content, request.config_format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Validate
    is_valid, errors = validate_config(config)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid config: {'; '.join(errors)}")

    # Safety guard: fuzzing a non-loopback target requires explicit operator
    # confirmation, because malformed traffic can disrupt live medical devices.
    from medaudit.fuzzer.safety import is_loopback_target
    target_host = config.get("target_host", "localhost")
    if not is_loopback_target(target_host) and not request.confirm_target:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Target '{target_host}' is not localhost. Fuzzing sends malformed "
                f"traffic that can crash or disrupt live medical devices. Re-submit "
                f"with confirm_target=true to acknowledge you are authorized to test "
                f"this host."
            ),
        )

    # Create job record
    job = FuzzingJob(
        project_id=project_id,
        name=request.name,
        target_host=config.get("target_host", "localhost"),
        target_port=config.get("target_port", 2575),
        use_tls=config.get("use_tls", False),
        config_format=request.config_format,
        config_content=request.config_content,
        status="pending"
    )
    
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Start fuzzing in background thread
    from .database import get_db_manager
    db_manager = get_db_manager()
    
    thread = threading.Thread(
        target=run_fuzzing_job,
        args=(job.id, config, db_manager.SessionLocal),
        kwargs={"project_id": project_id, "authorized": request.confirm_target}
    )
    thread.daemon = True
    thread.start()
    
    logger.info(f"Started fuzzing job {job.id} for project {project_id}")
    
    return {"success": True, "job": job.to_dict()}


@router.get("/projects/{project_id}/jobs")
async def list_fuzzing_jobs(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    List fuzzing jobs for a project.
    
    Args:
        project_id: Project ID
        
    Returns:
        List of fuzzing jobs
    """
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
    """
    Get details of a fuzzing job.
    
    Args:
        project_id: Project ID
        job_id: Job ID
        
    Returns:
        Job details including findings and live status if running
    """
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get real-time status if job is running
    live_status = get_job_status(job_id)
    
    result = job.to_dict()
    result["config_content"] = job.config_content
    result["findings"] = job.findings or (live_status.get("findings", []) if live_status else [])
    
    if live_status:
        result["live_progress"] = live_status.get("progress", job.progress)
        result["live_total_requests"] = live_status.get("total_requests", job.total_requests)
        result["live_status"] = live_status.get("status", job.status)
        result["live_successful"] = live_status.get("successful", 0)
        result["live_errors"] = live_status.get("errors", 0)
        result["live_interesting"] = live_status.get("interesting", 0)
    
    return {"job": result}


@router.post("/projects/{project_id}/jobs/{job_id}/stop")
async def stop_fuzzing_job(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Stop a running fuzzing job.
    
    Args:
        project_id: Project ID
        job_id: Job ID to stop
        
    Returns:
        Success status
    """
    # Verify ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Signal job to stop
    engine_stop_job(job_id)
    
    # Update database
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if job:
        job.status = "stopped"
        db.commit()
        logger.info(f"Stopped fuzzing job {job_id}")
    
    return {"success": True}


@router.delete("/projects/{project_id}/jobs/{job_id}")
async def delete_fuzzing_job(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Delete a fuzzing job.
    
    Args:
        project_id: Project ID
        job_id: Job ID to delete
        
    Returns:
        Success status
    """
    # Verify ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Stop if running
    engine_stop_job(job_id)
    
    db.delete(job)
    db.commit()
    
    logger.info(f"Deleted fuzzing job {job_id}")
    
    return {"success": True}


# ============================================================================
# Additional utility endpoints for the fuzzer
# ============================================================================

@router.get("/strategies")
async def list_strategies(user: User = Depends(require_auth)):
    """
    List available fuzzing strategies.
    
    Returns descriptions of all available mutation strategies.
    """
    return {
        "field_strategies": {
            "all": "Apply all mutation types",
            "random": "Random mutations",
            "empty": "Empty string",
            "null": "Null bytes",
            "overflow": "Buffer overflow (long strings)",
            "special": "Special characters (HL7 delimiters, control chars)",
            "sql": "SQL injection payloads",
            "format": "Format string attacks",
            "cmd": "Command injection",
            "unicode": "Unicode edge cases",
            "boundary": "Boundary values (numeric limits, dates)",
            "custom": "User-defined values"
        },
        "segment_strategies": {
            "add": "Inject additional segments",
            "remove": "Remove segments",
            "reorder": "Shuffle segment order"
        },
        "message_strategies": {
            "delimiter": "Mutate HL7 delimiters"
        }
    }


@router.post("/quick-test")
async def quick_test(
    host: str,
    port: int = 2575,
    message: str = None,
    use_tls: bool = False,
    user: User = Depends(require_auth)
):
    """
    Send a quick test message to an HL7 server.
    
    Args:
        host: Target hostname
        port: Target port
        message: Optional HL7 message (uses default if not provided)
        use_tls: Whether to use TLS
        
    Returns:
        Response from the server
    """
    if not message:
        message = (
            "MSH|^~\\&|MEDAUDIT|TEST|TARGET|DEVICE|{timestamp}||ADT^A01|{msg_id}|P|2.5\r"
            "PID|1||TEST123||TEST^USER||19800101|M"
        )
    
    result = send_hl7_message(host, port, message, use_tls)
    return result


@router.get("/projects/{project_id}/jobs/{job_id}/logs/download/detailed")
async def download_detailed_traffic_logs(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Download detailed traffic logs (JSON Lines format) for a specific fuzzing job.
    
    Returns:
        JSON Lines file with all requests and responses
    """
    from medaudit.web.database import FuzzingJob
    from fastapi.responses import FileResponse
    
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not job.detailed_traffic_log or not Path(job.detailed_traffic_log).exists():
        raise HTTPException(status_code=404, detail="Traffic log not found")
    
    return FileResponse(
        path=job.detailed_traffic_log,
        filename=f"traffic_detailed_{job_id}.jsonl",
        media_type="application/json"
    )


@router.get("/projects/{project_id}/jobs/{job_id}/logs/download/findings")
async def download_findings_logs(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Download findings logs (JSON Lines format) for a specific fuzzing job.
    
    Returns:
        JSON Lines file with all interesting findings
    """
    from medaudit.web.database import FuzzingJob
    from fastapi.responses import FileResponse
    
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not job.findings_log or not Path(job.findings_log).exists():
        raise HTTPException(status_code=404, detail="Findings log not found")
    
    return FileResponse(
        path=job.findings_log,
        filename=f"findings_{job_id}.jsonl",
        media_type="application/json"
    )


@router.get("/projects/{project_id}/jobs/{job_id}/logs/download/summary")
async def download_summary_logs(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Download summary report (JSON format) for a specific fuzzing job.
    
    Returns:
        JSON file with job summary and statistics
    """
    from medaudit.web.database import FuzzingJob
    from fastapi.responses import FileResponse
    
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not job.summary_log or not Path(job.summary_log).exists():
        raise HTTPException(status_code=404, detail="Summary log not found")
    
    return FileResponse(
        path=job.summary_log,
        filename=f"summary_{job_id}.json",
        media_type="application/json"
    )


@router.get("/projects/{project_id}/jobs/{job_id}/logs/summary")
async def get_logs_summary(
    project_id: str,
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Get information about available logs for a fuzzing job.
    
    Returns:
        Information about log files and their paths
    """
    from medaudit.web.database import FuzzingJob
    
    job = db.query(FuzzingJob).filter(
        FuzzingJob.id == job_id,
        FuzzingJob.project_id == project_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    from pathlib import Path
    
    # Check which logs exist
    logs_info = {
        "job_id": job_id,
        "job_name": job.name,
        "log_directory": job.traffic_log_dir,
        "available_logs": {
            "detailed_traffic_log": {
                "path": job.detailed_traffic_log,
                "exists": job.detailed_traffic_log and Path(job.detailed_traffic_log).exists(),
                "download_url": f"/api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/download/detailed"
            },
            "findings_log": {
                "path": job.findings_log,
                "exists": job.findings_log and Path(job.findings_log).exists(),
                "download_url": f"/api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/download/findings"
            },
            "summary_log": {
                "path": job.summary_log,
                "exists": job.summary_log and Path(job.summary_log).exists(),
                "download_url": f"/api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/download/summary"
            }
        }
    }
    
    return logs_info
