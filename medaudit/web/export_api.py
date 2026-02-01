"""
PDF Export API for Medaudit Web Application.
Generates PDF reports for security audit projects.
"""

import io
from datetime import datetime
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .database import get_db, Project, PcapAnalysis, FuzzingJob, ClientSession, ServerInstance, User
from .auth import require_auth

router = APIRouter(prefix="/api/export", tags=["export"])


def generate_project_report_pdf(project: Project, db: Session) -> bytes:
    """
    Generate a PDF report for a project.
    Uses reportlab for PDF generation.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus.flowables import HRFlowable
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#1e293b')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor('#2563eb')
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubheading',
        parent=styles['Heading3'],
        fontSize=12,
        spaceBefore=15,
        spaceAfter=8,
        textColor=colors.HexColor('#475569')
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    story = []
    
    # Title
    story.append(Paragraph(f"Security Audit Report", title_style))
    story.append(Paragraph(f"<b>Project:</b> {project.name}", body_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563eb')))
    story.append(Spacer(1, 20))
    
    # Project Details
    story.append(Paragraph("Project Information", heading_style))
    
    project_data = [
        ["Field", "Value"],
        ["Project Name", project.name],
        ["Description", project.description or "N/A"],
        ["Status", project.status.upper()],
        ["Created", project.created_at.strftime('%Y-%m-%d %H:%M') if project.created_at else "N/A"],
    ]
    
    if project.engagement_start:
        project_data.append(["Engagement Start", project.engagement_start.strftime('%Y-%m-%d')])
    if project.engagement_end:
        project_data.append(["Engagement End", project.engagement_end.strftime('%Y-%m-%d')])
    
    project_table = Table(project_data, colWidths=[2*inch, 4.5*inch])
    project_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(project_table)
    story.append(Spacer(1, 20))
    
    # Traffic Analysis Summary
    pcap_analyses = db.query(PcapAnalysis).filter(PcapAnalysis.project_id == project.id).all()
    
    if pcap_analyses:
        story.append(Paragraph("Traffic Analysis Summary", heading_style))
        
        total_packets = sum(a.total_packets or 0 for a in pcap_analyses)
        total_hl7 = sum(a.hl7_message_count or 0 for a in pcap_analyses)
        total_pii = sum(a.pii_count or 0 for a in pcap_analyses)
        
        summary_data = [
            ["Metric", "Value"],
            ["Total PCAP Files Analyzed", str(len(pcap_analyses))],
            ["Total Packets", str(total_packets)],
            ["HL7 Messages Detected", str(total_hl7)],
            ["PII Findings", str(total_pii)],
        ]
        
        # Encryption breakdown
        encryption_counts = {}
        for a in pcap_analyses:
            status = a.encryption_status or "unknown"
            encryption_counts[status] = encryption_counts.get(status, 0) + 1
        
        for status, count in encryption_counts.items():
            summary_data.append([f"Encryption: {status.replace('_', ' ').title()}", str(count)])
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16a34a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0fdf4')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bbf7d0')),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 15))
        
        # Individual PCAP analyses
        story.append(Paragraph("PCAP Analysis Details", subheading_style))
        
        for analysis in pcap_analyses:
            story.append(Paragraph(f"<b>File:</b> {analysis.filename}", body_style))
            
            analysis_data = [
                ["Packets", str(analysis.total_packets or 0)],
                ["HL7 Messages", str(analysis.hl7_message_count or 0)],
                ["PII Findings", str(analysis.pii_count or 0)],
                ["Encryption", (analysis.encryption_status or "unknown").replace("_", " ").title()],
            ]
            
            analysis_table = Table(analysis_data, colWidths=[2*inch, 2*inch])
            analysis_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#e2e8f0')),
            ]))
            story.append(analysis_table)
            story.append(Spacer(1, 10))
    
    # Fuzzing Results
    fuzzing_jobs = db.query(FuzzingJob).filter(FuzzingJob.project_id == project.id).all()
    
    if fuzzing_jobs:
        story.append(PageBreak())
        story.append(Paragraph("Fuzzing Results", heading_style))
        
        for job in fuzzing_jobs:
            story.append(Paragraph(f"<b>Job:</b> {job.name}", body_style))
            story.append(Paragraph(f"<b>Target:</b> {job.target_host}:{job.target_port}", body_style))
            story.append(Paragraph(f"<b>Status:</b> {job.status.upper()}", body_style))
            
            job_data = [
                ["Metric", "Value"],
                ["Total Requests", str(job.total_requests)],
                ["Successful", str(job.successful_requests)],
                ["Errors", str(job.error_requests)],
                ["Interesting Findings", str(job.interesting_findings)],
            ]
            
            job_table = Table(job_data, colWidths=[2.5*inch, 2*inch])
            job_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d97706')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fffbeb')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#fde68a')),
            ]))
            story.append(job_table)
            
            # Add findings if any
            if job.findings:
                story.append(Spacer(1, 10))
                story.append(Paragraph("<b>Key Findings:</b>", body_style))
                
                for i, finding in enumerate(job.findings[:10]):  # First 10 findings
                    finding_text = f"{i+1}. [{finding.get('finding_type', 'unknown')}] {finding.get('rule', 'Unknown rule')} - {finding.get('mutation', 'Unknown mutation')}"
                    story.append(Paragraph(finding_text, body_style))
                
                if len(job.findings) > 10:
                    story.append(Paragraph(f"... and {len(job.findings) - 10} more findings", body_style))
            
            story.append(Spacer(1, 15))
    
    # Client Sessions
    client_sessions = db.query(ClientSession).filter(ClientSession.project_id == project.id).all()
    
    if client_sessions:
        story.append(Paragraph("Client Sessions", heading_style))
        
        session_data = [["Target", "Messages Sent", "Status"]]
        for session in client_sessions:
            msg_count = len(session.message_history) if session.message_history else 0
            session_data.append([
                f"{session.target_host}:{session.target_port}",
                str(msg_count),
                session.status.upper()
            ])
        
        session_table = Table(session_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        session_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7c3aed')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f3ff')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c4b5fd')),
        ]))
        story.append(session_table)
        story.append(Spacer(1, 15))
    
    # Server Instances
    servers = db.query(ServerInstance).filter(ServerInstance.project_id == project.id).all()
    
    if servers:
        story.append(Paragraph("Mock Servers", heading_style))
        
        server_data = [["Name", "Address", "TLS", "Messages Received"]]
        for server in servers:
            server_data.append([
                server.name,
                f"{server.host}:{server.port}",
                "Yes" if server.use_tls else "No",
                str(server.total_messages)
            ])
        
        server_table = Table(server_data, colWidths=[2*inch, 2*inch, 1*inch, 1.5*inch])
        server_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0891b2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecfeff')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#a5f3fc')),
        ]))
        story.append(server_table)
    
    # Footer
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"<i>Report generated by Medaudit 2.0 - Medical Device Security Analysis Tool</i>",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.gray)
    ))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


@router.get("/projects/{project_id}/pdf")
async def export_project_pdf(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Export a project report as PDF."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    try:
        pdf_content = generate_project_report_pdf(project, db)
        
        filename = f"medaudit_report_{project.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PDF generation requires reportlab. Install with: pip install reportlab"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@router.get("/projects/{project_id}/json")
async def export_project_json(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Export a project as JSON."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Gather all project data
    export_data = {
        "project": project.to_dict(),
        "exported_at": datetime.now().isoformat(),
        "pcap_analyses": [a.to_dict() for a in project.pcap_analyses],
        "fuzzing_jobs": [j.to_dict() for j in project.fuzzing_jobs],
        "client_sessions": [s.to_dict() for s in project.client_sessions],
        "server_instances": [s.to_dict() for s in project.server_instances]
    }
    
    return export_data
