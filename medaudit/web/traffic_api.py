"""
Traffic Analysis API for Medaudit Web Application.
Provides PCAP upload, analysis, and network flow visualization.
"""

import os
import tempfile
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from .database import get_db, Project, PcapAnalysis, User
from .auth import require_auth
from .analyzer import analyze_pcap_detailed
from medaudit.utils import get_artifacts_dir

router = APIRouter(prefix="/api/traffic", tags=["traffic"])

# Artifacts base path (from centralized paths module)
ARTIFACTS_BASE_PATH = get_artifacts_dir()


def generate_network_graph(analysis_results: dict) -> dict:
    """
    Generate network graph data from PCAP analysis results.
    Returns data suitable for Cytoscape.js visualization.
    """
    nodes = {}
    edges = []
    edge_data = defaultdict(lambda: {
        "packet_count": 0,
        "hl7_messages": 0,
        "encrypted": False,
        "protocols": set()
    })
    
    # Process connections
    connections = analysis_results.get("connections", [])
    hl7_messages = analysis_results.get("hl7_messages", [])
    
    # Create message lookup by source/dest
    message_counts = defaultdict(int)
    for msg in hl7_messages:
        key = f"{msg.get('source', '')}_{msg.get('destination', '')}"
        message_counts[key] += 1
    
    for conn in connections:
        src_ip = conn.get("source_ip", "unknown")
        dst_ip = conn.get("dest_ip", "unknown")
        src_port = conn.get("source_port", 0)
        dst_port = conn.get("dest_port", 0)
        
        # Add nodes
        if src_ip not in nodes:
            nodes[src_ip] = {
                "id": src_ip,
                "label": src_ip,
                "type": "host",
                "ports": set(),
                "packet_count": 0,
                "is_hl7_source": False,
                "is_hl7_dest": False
            }
        nodes[src_ip]["ports"].add(src_port)
        nodes[src_ip]["packet_count"] += conn.get("packet_count", 0)
        
        if dst_ip not in nodes:
            nodes[dst_ip] = {
                "id": dst_ip,
                "label": dst_ip,
                "type": "host",
                "ports": set(),
                "packet_count": 0,
                "is_hl7_source": False,
                "is_hl7_dest": False
            }
        nodes[dst_ip]["ports"].add(dst_port)
        
        # Check if this is HL7 traffic (common HL7 port)
        if dst_port == 2575 or src_port == 2575:
            nodes[src_ip]["is_hl7_source"] = True
            nodes[dst_ip]["is_hl7_dest"] = True
        
        # Add edge
        edge_key = f"{src_ip}_{dst_ip}"
        edge_data[edge_key]["packet_count"] += conn.get("packet_count", 0)
        edge_data[edge_key]["encrypted"] = conn.get("encrypted", False)
        edge_data[edge_key]["protocols"].add(conn.get("protocol", "TCP"))
        
        # Check for HL7 messages on this connection
        msg_key = f"{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        edge_data[edge_key]["hl7_messages"] += message_counts.get(msg_key, 0)
    
    # Convert to Cytoscape format
    cytoscape_nodes = []
    for node_id, node_data in nodes.items():
        node_type = "device"
        if node_data.get("is_hl7_dest"):
            node_type = "medical_device"
        elif node_data.get("is_hl7_source"):
            node_type = "client"
        
        cytoscape_nodes.append({
            "data": {
                "id": node_id,
                "label": node_id,
                "type": node_type,
                "ports": list(node_data["ports"]),
                "packet_count": node_data["packet_count"]
            }
        })
    
    cytoscape_edges = []
    for edge_key, data in edge_data.items():
        src, dst = edge_key.split("_", 1)
        
        # Determine edge type
        edge_type = "normal"
        if data["encrypted"]:
            edge_type = "encrypted"
        elif data["hl7_messages"] > 0:
            edge_type = "hl7"
        
        cytoscape_edges.append({
            "data": {
                "id": edge_key,
                "source": src,
                "target": dst,
                "type": edge_type,
                "packet_count": data["packet_count"],
                "hl7_messages": data["hl7_messages"],
                "encrypted": data["encrypted"],
                "protocols": list(data["protocols"])
            }
        })
    
    return {
        "nodes": cytoscape_nodes,
        "edges": cytoscape_edges,
        "stats": {
            "total_nodes": len(cytoscape_nodes),
            "total_edges": len(cytoscape_edges),
            "hl7_connections": sum(1 for e in cytoscape_edges if e["data"]["hl7_messages"] > 0),
            "encrypted_connections": sum(1 for e in cytoscape_edges if e["data"]["encrypted"])
        }
    }


def generate_sequence_diagram(analysis_results: dict) -> List[dict]:
    """
    Generate sequence diagram data from HL7 messages.
    Returns a list of message events in chronological order.
    """
    hl7_messages = analysis_results.get("hl7_messages", [])
    
    events = []
    for i, msg in enumerate(hl7_messages):
        events.append({
            "index": i,
            "source": msg.get("source", "Unknown"),
            "destination": msg.get("destination", "Unknown"),
            "message_type": msg.get("message_type", "Unknown"),
            "message_id": msg.get("message_control_id", ""),
            "timestamp": msg.get("message_datetime", ""),
            "segment_count": msg.get("segment_count", 0),
            "has_patient_info": bool(msg.get("patient_info"))
        })
    
    return events


@router.post("/projects/{project_id}/upload")
async def upload_pcap(
    project_id: str,
    file: UploadFile = File(...),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Upload and analyze a PCAP file."""
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    valid_extensions = ['.pcap', '.pcapng', '.cap']
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in valid_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Accepted: {', '.join(valid_extensions)}"
        )
    
    # Save file to project artifacts
    artifacts_path = project.get_artifacts_path(ARTIFACTS_BASE_PATH)
    pcaps_path = artifacts_path / "pcaps"
    pcaps_path.mkdir(exist_ok=True)
    
    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{file.filename}"
    file_path = pcaps_path / safe_filename
    
    # Save file
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Analyze PCAP
    try:
        results = analyze_pcap_detailed(str(file_path))
        
        if not results.get("success"):
            raise HTTPException(status_code=500, detail=results.get("error", "Analysis failed"))
        
        # Generate network graph
        network_graph = generate_network_graph(results)
        results["network_graph"] = network_graph
        
        # Generate sequence diagram
        sequence_diagram = generate_sequence_diagram(results)
        results["sequence_diagram"] = sequence_diagram
        
        # Save analysis to database
        analysis = PcapAnalysis(
            project_id=project_id,
            filename=file.filename,
            file_path=str(file_path),
            file_size=len(content),
            results=results,
            total_packets=results.get("summary", {}).get("total_packets", 0),
            hl7_message_count=results.get("summary", {}).get("hl7_message_count", 0),
            pii_count=results.get("summary", {}).get("pii_count", 0),
            encryption_status=results.get("encryption", {}).get("status", "unknown")
        )
        
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
        
        return {
            "success": True,
            "analysis": analysis.to_dict()
        }
        
    except Exception as e:
        # Clean up file on error
        if file_path.exists():
            file_path.unlink()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/projects/{project_id}/analyses")
async def list_analyses(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List all PCAP analyses for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    analyses = db.query(PcapAnalysis).filter(
        PcapAnalysis.project_id == project_id
    ).order_by(PcapAnalysis.created_at.desc()).all()
    
    return {"analyses": [a.to_dict() for a in analyses]}


@router.get("/projects/{project_id}/analyses/{analysis_id}")
async def get_analysis(
    project_id: str,
    analysis_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get a specific PCAP analysis with full results."""
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    analysis = db.query(PcapAnalysis).filter(
        PcapAnalysis.id == analysis_id,
        PcapAnalysis.project_id == project_id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return {"analysis": analysis.to_dict()}


@router.get("/projects/{project_id}/analyses/{analysis_id}/graph")
async def get_network_graph(
    project_id: str,
    analysis_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get network graph data for visualization."""
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    analysis = db.query(PcapAnalysis).filter(
        PcapAnalysis.id == analysis_id,
        PcapAnalysis.project_id == project_id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    results = analysis.results or {}
    
    # Regenerate graph if not in results
    if "network_graph" not in results:
        graph = generate_network_graph(results)
    else:
        graph = results["network_graph"]
    
    return {"graph": graph}


@router.get("/projects/{project_id}/analyses/{analysis_id}/sequence")
async def get_sequence_diagram(
    project_id: str,
    analysis_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get sequence diagram data for message flow visualization."""
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    analysis = db.query(PcapAnalysis).filter(
        PcapAnalysis.id == analysis_id,
        PcapAnalysis.project_id == project_id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    results = analysis.results or {}
    
    # Regenerate sequence if not in results
    if "sequence_diagram" not in results:
        sequence = generate_sequence_diagram(results)
    else:
        sequence = results["sequence_diagram"]
    
    return {"sequence": sequence}


@router.delete("/projects/{project_id}/analyses/{analysis_id}")
async def delete_analysis(
    project_id: str,
    analysis_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Delete a PCAP analysis and its file."""
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    analysis = db.query(PcapAnalysis).filter(
        PcapAnalysis.id == analysis_id,
        PcapAnalysis.project_id == project_id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Delete file
    if analysis.file_path:
        file_path = Path(analysis.file_path)
        if file_path.exists():
            file_path.unlink()
    
    db.delete(analysis)
    db.commit()
    
    return {"success": True}


@router.get("/projects/{project_id}/summary")
async def get_traffic_summary(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Get a summary of all traffic analyses for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    analyses = db.query(PcapAnalysis).filter(
        PcapAnalysis.project_id == project_id
    ).all()
    
    # Aggregate stats
    total_packets = sum(a.total_packets or 0 for a in analyses)
    total_hl7 = sum(a.hl7_message_count or 0 for a in analyses)
    total_pii = sum(a.pii_count or 0 for a in analyses)
    
    encryption_counts = defaultdict(int)
    for a in analyses:
        status = a.encryption_status or "unknown"
        encryption_counts[status] += 1
    
    return {
        "project_id": project_id,
        "analysis_count": len(analyses),
        "total_packets": total_packets,
        "total_hl7_messages": total_hl7,
        "total_pii_findings": total_pii,
        "encryption_breakdown": dict(encryption_counts)
    }
