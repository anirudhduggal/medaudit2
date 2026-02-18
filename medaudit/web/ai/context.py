"""
Context Engine for Medaudit AI Assistant

Collects real-time state from all modules to provide the AI with 
comprehensive awareness of the current pentest session.

Modules monitored:
- Server: Active servers, connection logs, received messages
- Client: Sent payloads, responses, error patterns
- Fuzzer: Active jobs, findings, progress
- Traffic: PCAP analysis results, PII findings, encryption status
- Project: Overall project metadata and configuration
"""

import time
import threading
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class ContextEngine:
    """
    Collects and manages context from all Medaudit modules.
    
    Maintains a rolling buffer of events and provides summarized
    context suitable for AI prompt injection.
    """
    
    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._unprocessed_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._max_events = 500
        self._last_analysis_time = 0.0
        self.analysis_interval = 30.0  # Seconds between auto-analyses
    
    def add_event(self, module: str, event_type: str, data: Dict[str, Any]):
        """
        Add an event from any module.
        
        Args:
            module: Source module (server, client, fuzzer, traffic, project)
            event_type: Type of event (message_received, payload_sent, finding, etc.)
            data: Event-specific data
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": module,
            "event_type": event_type,
            "data": data,
        }
        
        with self._lock:
            self._events.append(event)
            self._unprocessed_events.append(event)
            
            # Trim old events
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events:]
    
    def get_unprocessed_events(self) -> List[Dict[str, Any]]:
        """Get events that haven't been analyzed yet and mark them as processed."""
        with self._lock:
            events = self._unprocessed_events.copy()
            self._unprocessed_events.clear()
            return events
    
    def has_pending_events(self) -> bool:
        """Check if there are unprocessed events waiting for analysis."""
        with self._lock:
            return len(self._unprocessed_events) > 0
    
    def should_auto_analyze(self) -> bool:
        """Check if enough time has passed and there are events to analyze."""
        now = time.time()
        if now - self._last_analysis_time < self.analysis_interval:
            return False
        return self.has_pending_events()
    
    def mark_analyzed(self):
        """Mark that an auto-analysis was just performed."""
        self._last_analysis_time = time.time()
    
    def build_context(
        self,
        project_id: str,
        db: Session,
        include_full_logs: bool = False,
    ) -> str:
        """
        Build a comprehensive context string for the AI.
        
        Collects state from all modules and formats it for prompt injection.
        
        Args:
            project_id: Current project ID
            db: Database session
            include_full_logs: If True, include detailed logs (more tokens)
            
        Returns: Formatted context string
        """
        from ..database import (
            Project, ServerInstance, FuzzingJob, PcapAnalysis, ClientSession
        )
        
        sections = []
        
        # === Project Overview ===
        project = db.query(Project).filter(Project.id == project_id).first()
        if project:
            sections.append(self._format_project_context(project))
        
        # === Server Status ===
        servers = db.query(ServerInstance).filter(
            ServerInstance.project_id == project_id
        ).all()
        if servers:
            sections.append(self._format_server_context(servers, include_full_logs))
        
        # === Fuzzer Status ===
        jobs = db.query(FuzzingJob).filter(
            FuzzingJob.project_id == project_id
        ).order_by(FuzzingJob.created_at.desc()).limit(5).all()
        if jobs:
            sections.append(self._format_fuzzer_context(jobs))
        
        # === Traffic/PCAP Analysis ===
        analyses = db.query(PcapAnalysis).filter(
            PcapAnalysis.project_id == project_id
        ).order_by(PcapAnalysis.created_at.desc()).limit(3).all()
        if analyses:
            sections.append(self._format_traffic_context(analyses))
        
        # === Client Sessions ===
        sessions = db.query(ClientSession).filter(
            ClientSession.project_id == project_id
        ).order_by(ClientSession.created_at.desc()).limit(3).all()
        if sessions:
            sections.append(self._format_client_context(sessions))
        
        # === Recent Events ===
        with self._lock:
            recent_events = self._events[-30:]  # Last 30 events
        if recent_events:
            sections.append(self._format_recent_events(recent_events))
        
        if not sections:
            return "No project data available yet. The project appears to be newly created with no activity."
        
        return "\n\n".join(sections)
    
    def build_event_context(self, events: List[Dict[str, Any]]) -> str:
        """Build context from a specific set of events (for auto-analyze)."""
        if not events:
            return "No new events."
        
        lines = ["## New Events Since Last Analysis"]
        for event in events:
            module = event.get("module", "unknown")
            event_type = event.get("event_type", "unknown")
            data = event.get("data", {})
            timestamp = event.get("timestamp", "")
            
            summary = self._summarize_event(module, event_type, data)
            lines.append(f"- [{timestamp}] [{module.upper()}] {summary}")
        
        return "\n".join(lines)
    
    # =========================================================================
    # Context Formatters
    # =========================================================================
    
    def _format_project_context(self, project) -> str:
        """Format project overview."""
        lines = [
            "## Project Overview",
            f"- **Name**: {project.name}",
            f"- **Description**: {project.description or 'None'}",
            f"- **Status**: {project.status}",
            f"- **Created**: {project.created_at}",
            f"- **PCAPs Analyzed**: {len(project.pcap_analyses) if project.pcap_analyses else 0}",
            f"- **Fuzzing Jobs**: {len(project.fuzzing_jobs) if project.fuzzing_jobs else 0}",
            f"- **Server Instances**: {len(project.server_instances) if project.server_instances else 0}",
        ]
        return "\n".join(lines)
    
    def _format_server_context(self, servers, include_logs: bool) -> str:
        """Format server module context."""
        from ..server_api import _active_servers
        
        lines = ["## HL7 Servers"]
        for server in servers:
            # Check live status
            live_status = "unknown"
            live_connections = 0
            live_messages = 0
            
            if server.id in _active_servers:
                live = _active_servers[server.id]
                live_status = live.get("status", "unknown")
                if "server" in live:
                    live_connections = live["server"].connections
                    live_messages = live["server"].messages
            
            lines.append(f"### Server: {server.name}")
            lines.append(f"- Host: {server.host}:{server.port}")
            lines.append(f"- TLS: {'Yes' if server.use_tls else 'No'}")
            lines.append(f"- Status: {live_status}")
            lines.append(f"- Total Connections: {live_connections}")
            lines.append(f"- Total Messages: {live_messages}")
            
            if include_logs and server.id in _active_servers and "server" in _active_servers[server.id]:
                recent_logs = _active_servers[server.id]["server"].message_log[-10:]
                if recent_logs:
                    lines.append("- Recent Activity:")
                    for log in recent_logs:
                        evt = log.get("event_type", "")
                        data = log.get("data", {})
                        lines.append(f"  - [{evt}] {self._summarize_event('server', evt, data)}")
        
        return "\n".join(lines)
    
    def _format_fuzzer_context(self, jobs) -> str:
        """Format fuzzer module context."""
        from medaudit.fuzzer.engine import get_job_status
        
        lines = ["## Fuzzing Jobs"]
        for job in jobs:
            live_status = get_job_status(job.id)
            
            lines.append(f"### Job: {job.name}")
            lines.append(f"- Target: {job.target_host}:{job.target_port}")
            lines.append(f"- Status: {live_status.get('status', job.status) if live_status else job.status}")
            
            progress = live_status.get("progress", job.progress) if live_status else job.progress
            lines.append(f"- Progress: {progress}%")
            
            total = live_status.get("total_requests", job.total_requests) if live_status else job.total_requests
            errors = live_status.get("errors", job.error_requests) if live_status else job.error_requests
            interesting = live_status.get("interesting", job.interesting_findings) if live_status else job.interesting_findings
            
            lines.append(f"- Requests: {total} total, {errors} errors, {interesting} interesting")
            
            # Include findings
            findings = job.findings or (live_status.get("findings", []) if live_status else [])
            if findings:
                lines.append(f"- **Findings ({len(findings)}):**")
                for f in findings[-5]:  # Last 5 findings
                    finding_type = f.get("finding_type", "unknown")
                    rule = f.get("rule", "unknown")
                    lines.append(f"  - [{finding_type}] {rule}: {f.get('mutation', '')[:100]}")
        
        return "\n".join(lines)
    
    def _format_traffic_context(self, analyses) -> str:
        """Format traffic/PCAP analysis context."""
        lines = ["## PCAP Traffic Analysis"]
        for analysis in analyses:
            lines.append(f"### PCAP: {analysis.filename}")
            lines.append(f"- Total Packets: {analysis.total_packets}")
            lines.append(f"- HL7 Messages: {analysis.hl7_message_count}")
            lines.append(f"- PII Findings: {analysis.pii_count}")
            lines.append(f"- Encryption: {analysis.encryption_status}")
            
            # Include summary from results
            results = analysis.results or {}
            summary = results.get("summary", {})
            if summary:
                if summary.get("unique_message_types"):
                    lines.append(f"- Message Types: {', '.join(summary['unique_message_types'])}")
            
            # PII details
            pii = results.get("pii_findings", [])
            if pii:
                pii_types = set()
                for p in pii:
                    pii_types.add(p.get("type", p.get("entity_type", "unknown")))
                lines.append(f"- PII Types Found: {', '.join(pii_types)}")
            
            # Encryption details
            encryption = results.get("encryption", {})
            if encryption:
                lines.append(f"- Encryption Details: {encryption.get('status', 'unknown')}")
                if encryption.get("details"):
                    lines.append(f"  {encryption['details']}")
        
        return "\n".join(lines)
    
    def _format_client_context(self, sessions) -> str:
        """Format client session context."""
        lines = ["## Client Activity"]
        for session in sessions:
            lines.append(f"### Session to {session.target_host}:{session.target_port}")
            lines.append(f"- TLS: {'Yes' if session.use_tls else 'No'}")
            lines.append(f"- Status: {session.status}")
            
            history = session.message_history or []
            lines.append(f"- Messages Exchanged: {len(history)}")
            
            # Last few messages
            if history:
                lines.append("- Recent Messages:")
                for msg in history[-5:]:
                    direction = msg.get("direction", "unknown")
                    message_preview = (msg.get("message", ""))[:100]
                    error = msg.get("error")
                    if error:
                        lines.append(f"  - [{direction}] ERROR: {error}")
                    else:
                        lines.append(f"  - [{direction}] {message_preview}...")
        
        return "\n".join(lines)
    
    def _format_recent_events(self, events: List[Dict]) -> str:
        """Format recent events from the event buffer."""
        lines = ["## Recent Activity (Real-time)"]
        for event in events[-15:]:  # Last 15
            module = event.get("module", "unknown")
            event_type = event.get("event_type", "unknown")
            data = event.get("data", {})
            summary = self._summarize_event(module, event_type, data)
            lines.append(f"- [{module.upper()}] {summary}")
        return "\n".join(lines)
    
    def _summarize_event(self, module: str, event_type: str, data: dict) -> str:
        """Create a human-readable summary of an event."""
        if module == "server":
            if event_type == "connection":
                return f"Client {data.get('client', '?')} {data.get('action', 'event')}"
            elif event_type == "message_received":
                return f"Received {data.get('message_type', '?')} from {data.get('client', '?')} (ID: {data.get('message_id', '?')})"
            elif event_type == "message_sent":
                return f"Sent {data.get('type', 'ACK')} to {data.get('client', '?')}"
            elif event_type == "error":
                return f"Error: {data.get('error', 'unknown')}"
            elif event_type == "server":
                return f"Server {data.get('action', 'event')} on port {data.get('port', '?')}"
        
        elif module == "client":
            if event_type == "payload_sent":
                return f"Sent payload to {data.get('target', '?')} - Response: {data.get('response_status', '?')}"
            elif event_type == "error":
                return f"Client error: {data.get('error', 'unknown')}"
        
        elif module == "fuzzer":
            if event_type == "started":
                return f"Fuzzing started: {data.get('name', '?')} against {data.get('target', '?')}"
            elif event_type == "finding":
                return f"Finding: [{data.get('finding_type', '?')}] {data.get('rule', '?')}"
            elif event_type == "completed":
                return f"Fuzzing completed: {data.get('total', 0)} requests, {data.get('findings', 0)} findings"
            elif event_type == "stopped":
                return f"Fuzzing stopped at {data.get('progress', 0)}%"
        
        elif module == "traffic":
            if event_type == "pcap_uploaded":
                return f"PCAP uploaded: {data.get('filename', '?')} ({data.get('hl7_count', 0)} HL7 messages)"
            elif event_type == "pii_found":
                return f"PII detected: {data.get('count', 0)} findings"
        
        # Fallback
        return f"{event_type}: {str(data)[:100]}"


# Global context engine instance
context_engine = ContextEngine()
