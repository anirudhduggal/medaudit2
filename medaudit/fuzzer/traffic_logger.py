# Medaudit HL7 Fuzzer - Traffic Logger
# Logs all fuzzing traffic (requests/responses) to JSON Lines format

"""
Fuzzing Traffic Logger

This module provides comprehensive logging of all fuzzing traffic including:
- Request/response pairs
- Timing information
- Response status and findings
- Error information
- Rule and mutation details

Logs are stored in JSON Lines format (one JSON object per line) for easy parsing.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class FuzzingTrafficEntry:
    """Single fuzzing request/response entry."""
    timestamp: str
    sequence_number: int
    rule_name: str
    mutation_type: str
    original_value: Optional[str]
    request_message: str
    request_length: int
    response_message: Optional[str]
    response_length: int
    response_time_ms: float
    success: bool
    is_interesting: bool
    finding_type: Optional[str] = None
    error_message: Optional[str] = None
    status_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class FuzzingTrafficLogger:
    """
    Logs all fuzzing traffic to files in project-specific directories.
    
    Creates JSON Lines files with complete request/response information.
    Maintains separate detailed and summary logs.
    """

    def __init__(self, log_dir: Path, job_id: str, job_name: str):
        """
        Initialize the traffic logger.
        
        Args:
            log_dir: Base logging directory for the project
            job_id: Unique job ID
            job_name: Human-readable job name
        """
        self.log_dir = Path(log_dir)
        self.job_id = job_id
        self.job_name = job_name
        self.sequence = 0
        
        # Create job-specific directory
        self.job_log_dir = self.log_dir / job_id
        self.job_log_dir.mkdir(parents=True, exist_ok=True)
        
        # Log file paths
        self.detailed_log = self.job_log_dir / "traffic_detailed.jsonl"
        self.summary_log = self.job_log_dir / "traffic_summary.json"
        self.findings_log = self.job_log_dir / "findings.jsonl"
        self.metadata_file = self.job_log_dir / "metadata.json"
        
        # Initialize metadata
        self.start_time = datetime.utcnow().isoformat()
        self.stats = {
            "total_requests": 0,
            "successful_responses": 0,
            "failed_responses": 0,
            "interesting_findings": 0,
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "average_response_time_ms": 0.0,
            "min_response_time_ms": float('inf'),
            "max_response_time_ms": 0.0
        }
        self.response_times = []
        
        # Write initial metadata
        self._write_metadata()
    
    def log_traffic(
        self,
        request_message: str,
        response_message: Optional[str],
        response_time_ms: float,
        rule_name: str,
        mutation_type: str,
        success: bool,
        is_interesting: bool = False,
        finding_type: Optional[str] = None,
        error_message: Optional[str] = None,
        status_code: Optional[str] = None,
        original_value: Optional[str] = None
    ) -> None:
        """
        Log a single fuzzing request/response pair.
        
        Args:
            request_message: HL7 message sent
            response_message: Response received (if any)
            response_time_ms: Response time in milliseconds
            rule_name: Name of fuzzing rule applied
            mutation_type: Type of mutation
            success: Whether request was successful
            is_interesting: Whether response was marked as interesting
            finding_type: Type of finding if interesting
            error_message: Error details if failed
            status_code: Response status code if applicable
            original_value: Original field value before mutation
        """
        self.sequence += 1
        
        # Create entry
        entry = FuzzingTrafficEntry(
            timestamp=datetime.utcnow().isoformat(),
            sequence_number=self.sequence,
            rule_name=rule_name,
            mutation_type=mutation_type,
            original_value=original_value,
            request_message=request_message,
            request_length=len(request_message.encode('utf-8')),
            response_message=response_message,
            response_length=len(response_message.encode('utf-8')) if response_message else 0,
            response_time_ms=response_time_ms,
            success=success,
            is_interesting=is_interesting,
            finding_type=finding_type,
            error_message=error_message,
            status_code=status_code
        )
        
        # Write detailed log (JSON Lines)
        try:
            with open(self.detailed_log, 'a') as f:
                f.write(json.dumps(entry.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to write detailed traffic log: {e}")
        
        # Write findings if interesting
        if is_interesting:
            try:
                with open(self.findings_log, 'a') as f:
                    f.write(json.dumps({
                        **entry.to_dict(),
                        "finding_type": finding_type,
                        "details": {
                            "request_preview": request_message[:500],
                            "response_preview": response_message[:500] if response_message else None
                        }
                    }) + '\n')
            except Exception as e:
                logger.error(f"Failed to write findings log: {e}")
        
        # Update statistics
        self._update_stats(entry, success, is_interesting)
        
        # Periodically update metadata (every 10 requests)
        if self.sequence % 10 == 0:
            self._write_metadata()
    
    def _update_stats(self, entry: FuzzingTrafficEntry, success: bool, is_interesting: bool) -> None:
        """Update running statistics."""
        self.stats["total_requests"] += 1
        self.stats["total_bytes_sent"] += entry.request_length
        self.stats["total_bytes_received"] += entry.response_length
        
        if success:
            self.stats["successful_responses"] += 1
        else:
            self.stats["failed_responses"] += 1
        
        if is_interesting:
            self.stats["interesting_findings"] += 1
        
        # Track response times for averaging
        self.response_times.append(entry.response_time_ms)
        self.stats["min_response_time_ms"] = min(
            self.stats["min_response_time_ms"],
            entry.response_time_ms
        )
        self.stats["max_response_time_ms"] = max(
            self.stats["max_response_time_ms"],
            entry.response_time_ms
        )
        
        # Update average
        if self.response_times:
            self.stats["average_response_time_ms"] = sum(self.response_times) / len(self.response_times)
    
    def _write_metadata(self) -> None:
        """Write job metadata and statistics."""
        metadata = {
            "job_id": self.job_id,
            "job_name": self.job_name,
            "start_time": self.start_time,
            "last_updated": datetime.utcnow().isoformat(),
            "duration_seconds": (datetime.utcnow().fromisoformat(self.start_time) 
                                 if isinstance(self.start_time, str) else None),
            "statistics": self.stats,
            "log_files": {
                "detailed": str(self.detailed_log),
                "findings": str(self.findings_log),
                "metadata": str(self.metadata_file)
            }
        }
        
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write metadata: {e}")
    
    def finalize(self, final_status: str) -> Dict[str, Any]:
        """
        Finalize logging when job completes.
        
        Args:
            final_status: Job completion status (completed, stopped, error)
            
        Returns:
            Summary statistics
        """
        # Create summary log
        summary = {
            "job_id": self.job_id,
            "job_name": self.job_name,
            "start_time": self.start_time,
            "end_time": datetime.utcnow().isoformat(),
            "final_status": final_status,
            "statistics": self.stats,
            "log_files": {
                "detailed_traffic": self.detailed_log.name,
                "findings": self.findings_log.name,
                "metadata": self.metadata_file.name
            },
            "directory": str(self.job_log_dir)
        }
        
        try:
            with open(self.summary_log, 'w') as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write summary log: {e}")
        
        # Final metadata update
        self._write_metadata()
        
        logger.info(f"Fuzzing traffic logs written to {self.job_log_dir}")
        
        return summary
    
    @property
    def log_directory(self) -> Path:
        """Get the job log directory."""
        return self.job_log_dir
    
    def get_detailed_log_path(self) -> Path:
        """Get path to detailed traffic log."""
        return self.detailed_log
    
    def get_findings_log_path(self) -> Path:
        """Get path to findings log."""
        return self.findings_log
    
    def get_metadata_path(self) -> Path:
        """Get path to metadata file."""
        return self.metadata_file
    
    def get_summary_path(self) -> Path:
        """Get path to summary file."""
        return self.summary_log
