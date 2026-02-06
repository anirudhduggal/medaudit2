"""
Project Management API for Medaudit Web Application.
Handles CRUD operations for projects/workspaces.
"""

from datetime import datetime
from typing import Optional, List
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db, Project, User, PcapAnalysis
from .auth import require_auth
from medaudit.utils import get_artifacts_dir

router = APIRouter(prefix="/api/projects", tags=["projects"])

# Configurable artifacts path (from centralized paths module)
ARTIFACTS_BASE_PATH = get_artifacts_dir()


class ProjectCreate(BaseModel):
    """Schema for creating a project."""
    name: str
    description: Optional[str] = None
    engagement_start: Optional[datetime] = None
    engagement_end: Optional[datetime] = None


class ProjectUpdate(BaseModel):
    """Schema for updating a project."""
    name: Optional[str] = None
    description: Optional[str] = None
    engagement_start: Optional[datetime] = None
    engagement_end: Optional[datetime] = None
    status: Optional[str] = None


@router.get("")
async def list_projects(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    status: Optional[str] = None
):
    """List all projects for the current user."""
    query = db.query(Project).filter(Project.owner_id == user.id)
    
    if status:
        query = query.filter(Project.status == status)
    
    projects = query.order_by(Project.updated_at.desc()).all()
    
    return {
        "projects": [p.to_dict() for p in projects],
        "total": len(projects)
    }


@router.post("")
async def create_project(
    project_data: ProjectCreate,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Create a new project."""
    # Check if project with same name already exists for this user
    existing = db.query(Project).filter(
        Project.owner_id == user.id,
        Project.name == project_data.name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"A project named '{project_data.name}' already exists"
        )
    
    project = Project(
        name=project_data.name,
        description=project_data.description,
        owner_id=user.id,
        engagement_start=project_data.engagement_start,
        engagement_end=project_data.engagement_end
    )
    
    db.add(project)
    db.commit()
    db.refresh(project)
    
    # Create artifacts directory
    artifacts_path = project.get_artifacts_path(ARTIFACTS_BASE_PATH)
    (artifacts_path / "pcaps").mkdir(exist_ok=True)
    (artifacts_path / "reports").mkdir(exist_ok=True)
    (artifacts_path / "fuzzing").mkdir(exist_ok=True)
    
    return {"success": True, "project": project.to_dict()}


@router.get("/{project_id}")
async def get_project(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get a specific project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"project": project.to_dict()}


@router.put("/{project_id}")
async def update_project(
    project_id: str,
    project_data: ProjectUpdate,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Update a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Update fields
    if project_data.name is not None:
        project.name = project_data.name
    if project_data.description is not None:
        project.description = project_data.description
    if project_data.engagement_start is not None:
        project.engagement_start = project_data.engagement_start
    if project_data.engagement_end is not None:
        project.engagement_end = project_data.engagement_end
    if project_data.status is not None:
        project.status = project_data.status
    
    db.commit()
    db.refresh(project)
    
    return {"success": True, "project": project.to_dict()}


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Delete a project and all its data."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Stop any running servers for this project
    try:
        from .server_api import _active_servers
        from .database import ServerInstance
        servers = db.query(ServerInstance).filter(ServerInstance.project_id == project_id).all()
        for server in servers:
            if server.id in _active_servers and "server" in _active_servers[server.id]:
                _active_servers[server.id]["server"].stop()
                _active_servers[server.id]["status"] = "stopped"
    except Exception:
        pass  # Continue with deletion even if stopping fails
    
    # Stop any running fuzzing jobs for this project
    try:
        from medaudit.fuzzer.engine import stop_job
        from .database import FuzzingJob
        jobs = db.query(FuzzingJob).filter(
            FuzzingJob.project_id == project_id,
            FuzzingJob.status == "running"
        ).all()
        for job in jobs:
            stop_job(job.id)
    except Exception:
        pass  # Continue with deletion even if stopping fails
    
    # Delete artifacts directory (medaudit/data/artifacts/projects/<id>)
    import shutil
    artifacts_path = project.get_artifacts_path(ARTIFACTS_BASE_PATH)
    if artifacts_path.exists():
        shutil.rmtree(artifacts_path, ignore_errors=True)
    
    db.delete(project)
    db.commit()
    
    return {"success": True, "message": "Project and all associated data deleted"}


@router.get("/{project_id}/stats")
async def get_project_stats(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get statistics for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {
        "project_id": project_id,
        "stats": {
            "pcap_analyses": len(project.pcap_analyses),
            "client_sessions": len(project.client_sessions),
            "fuzzing_jobs": len(project.fuzzing_jobs),
            "server_instances": len(project.server_instances),
            "total_hl7_messages": sum(
                p.hl7_message_count or 0 for p in project.pcap_analyses
            ),
            "total_pii_findings": sum(
                p.pii_count or 0 for p in project.pcap_analyses
            )
        }
    }


@router.post("/{project_id}/duplicate")
async def duplicate_project(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Duplicate a project (creates copy without data)."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    new_project = Project(
        name=f"{project.name} (Copy)",
        description=project.description,
        owner_id=user.id,
        engagement_start=project.engagement_start,
        engagement_end=project.engagement_end,
        settings=project.settings.copy() if project.settings else {}
    )
    
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    
    # Create artifacts directory
    artifacts_path = new_project.get_artifacts_path(ARTIFACTS_BASE_PATH)
    (artifacts_path / "pcaps").mkdir(exist_ok=True)
    (artifacts_path / "reports").mkdir(exist_ok=True)
    (artifacts_path / "fuzzing").mkdir(exist_ok=True)
    
    return {"success": True, "project": new_project.to_dict()}
