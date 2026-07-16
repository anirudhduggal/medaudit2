# Medaudit HL7 Fuzzer - Fuzzing Engine
# Core fuzzing execution and message generation

"""
HL7 Fuzzing Engine

This module provides the core fuzzing execution engine including:
- Configuration parsing and validation
- Fuzzed message generation
- Job execution management
- Result collection and analysis

The engine can be used standalone via CLI or through the web API.
"""

import time
import yaml
import json
import logging
from datetime import datetime
from itertools import islice
from typing import Dict, Any, List, Optional, Generator
from pydantic import BaseModel

from .strategies import FuzzingStrategies
from .protocol import send_hl7_message
from .safety import check_authorization, apply_limits, TargetNotAuthorized

logger = logging.getLogger(__name__)

# Active jobs tracking (job_id -> status dict)
_active_jobs: Dict[str, Dict[str, Any]] = {}


class FuzzingRule(BaseModel):
    """
    Definition of a single fuzzing rule.
    
    Attributes:
        name: Human-readable rule name
        enabled: Whether this rule is active
        target: What to fuzz ('field', 'segment', or 'message')
        segment: Target segment for field mutations (e.g., 'PID', 'OBX')
        field_index: Field index within segment (0-based)
        strategy: Mutation strategy to apply
        iterations: Number of iterations for random strategies
        values: Custom values for 'custom' strategy
    """
    name: str
    enabled: bool = True
    target: str = "field"  # field, segment, message
    segment: Optional[str] = None
    field_index: Optional[int] = None
    strategy: str = "random"  # mutation type
    iterations: int = 10
    values: Optional[List[str]] = None  # custom values


class FuzzingConfig(BaseModel):
    """
    Complete fuzzing job configuration.
    
    Attributes:
        name: Job name
        target_host: Target HL7 server hostname
        target_port: Target HL7 server port
        use_tls: Whether to use TLS encryption
        base_message: HL7 message template to fuzz
        rules: List of fuzzing rules to apply
        delay_ms: Delay between requests in milliseconds
        timeout_seconds: Request timeout
        stop_on_error: Stop job on first error
        max_requests: Maximum number of requests to send
    """
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


def parse_fuzzing_config(content: str, format: str = "yaml") -> dict:
    """
    Parse fuzzing configuration from YAML or JSON string.
    
    Args:
        content: Configuration content string
        format: Format type ('yaml' or 'json')
        
    Returns:
        Parsed configuration dictionary
        
    Raises:
        ValueError: If parsing fails
        
    Example:
        >>> config = parse_fuzzing_config(yaml_content, "yaml")
        >>> print(config["target_host"])
    """
    try:
        if format.lower() == "yaml":
            return yaml.safe_load(content)
        else:
            return json.loads(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML configuration: {str(e)}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON configuration: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to parse {format} config: {str(e)}")


def validate_config(config: dict) -> tuple:
    """
    Validate a fuzzing configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Tuple of (is_valid: bool, errors: list)
        
    Example:
        >>> valid, errors = validate_config({"target_host": "localhost"})
        >>> if not valid:
        ...     print(errors)
    """
    errors = []
    
    # Required fields
    required = ["target_host", "base_message", "rules"]
    for field in required:
        if field not in config:
            errors.append(f"Missing required field: {field}")
    
    # Validate rules
    rules = config.get("rules", [])
    if not rules:
        errors.append("At least one fuzzing rule is required")
    
    for i, rule in enumerate(rules):
        if not rule.get("name"):
            errors.append(f"Rule {i}: missing name")
        
        target = rule.get("target", "field")
        if target == "field":
            if not rule.get("segment"):
                errors.append(f"Rule {i} ({rule.get('name', 'unnamed')}): field target requires 'segment'")
            if rule.get("field_index") is None:
                errors.append(f"Rule {i} ({rule.get('name', 'unnamed')}): field target requires 'field_index'")
    
    # Validate port
    port = config.get("target_port", 2575)
    if not isinstance(port, int) or port < 1 or port > 65535:
        errors.append(f"Invalid port: {port}")
    
    # Validate numeric fields
    if config.get("delay_ms", 100) < 0:
        errors.append("delay_ms cannot be negative")
    if config.get("timeout_seconds", 30) < 1:
        errors.append("timeout_seconds must be at least 1")
    if config.get("max_requests", 1000) < 1:
        errors.append("max_requests must be at least 1")
    
    return len(errors) == 0, errors


def generate_fuzzed_messages(
    base_message: str, 
    rules: List[dict]
) -> Generator[Dict[str, Any], None, None]:
    """
    Generate fuzzed messages based on fuzzing rules.
    
    This is a generator that yields mutated messages one at a time,
    allowing for efficient memory usage with large fuzzing campaigns.
    
    Args:
        base_message: Original HL7 message template
        rules: List of fuzzing rule dictionaries
        
    Yields:
        Dictionary containing:
        - message: The mutated HL7 message
        - rule: Name of the rule that generated it
        - mutation: Type of mutation applied
        - original_value: Original value that was mutated (if applicable)
        
    Example:
        >>> for msg_data in generate_fuzzed_messages(base_msg, rules):
        ...     print(f"Rule: {msg_data['rule']}, Mutation: {msg_data['mutation']}")
        ...     send_message(msg_data['message'])
    """
    strategies = FuzzingStrategies()
    
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        
        target = rule.get("target", "field")
        strategy = rule.get("strategy", "random")
        iterations = rule.get("iterations", 10)
        rule_name = rule.get("name", "unnamed")
        
        if target == "field":
            yield from _generate_field_mutations(
                base_message, rule, strategies
            )
        
        elif target == "segment":
            yield from _generate_segment_mutations(
                base_message, rule, strategies
            )
        
        elif target == "message":
            yield from _generate_message_mutations(
                base_message, rule, strategies
            )


def _generate_field_mutations(
    base_message: str,
    rule: dict,
    strategies: FuzzingStrategies
) -> Generator[Dict[str, Any], None, None]:
    """Generate field-level mutations."""
    segment_name = rule.get("segment", "PID")
    field_index = rule.get("field_index", 1)
    strategy = rule.get("strategy", "random")
    iterations = rule.get("iterations", 10)
    rule_name = rule.get("name", "unnamed")
    
    # Parse message into segments
    segments = base_message.split("\r")
    target_segment_idx = None
    
    for i, seg in enumerate(segments):
        if seg.startswith(segment_name + "|"):
            target_segment_idx = i
            break
    
    if target_segment_idx is None:
        logger.warning(f"Segment {segment_name} not found in message")
        return
    
    fields = segments[target_segment_idx].split("|")
    
    if field_index >= len(fields):
        logger.warning(f"Field index {field_index} out of range for segment {segment_name}")
        return
    
    original = fields[field_index]
    
    if strategy == "custom" and rule.get("values"):
        # Use custom values
        for value in rule["values"]:
            fields[field_index] = value
            segments[target_segment_idx] = "|".join(fields)
            yield {
                "message": "\r".join(segments),
                "rule": rule_name,
                "mutation": f"custom: {value[:50]}",
                "original_value": original
            }
            fields[field_index] = original
            segments[target_segment_idx] = "|".join(fields)
    
    elif strategy == "boundary":
        for value in strategies.generate_boundary_values():
            fields[field_index] = value
            segments[target_segment_idx] = "|".join(fields)
            yield {
                "message": "\r".join(segments),
                "rule": rule_name,
                "mutation": f"boundary: {value[:50]}",
                "original_value": original
            }
            fields[field_index] = original
            segments[target_segment_idx] = "|".join(fields)
    
    elif strategy == "all":
        mutation_types = [
            "empty", "null", "long", "special", "sql", 
            "format", "overflow", "cmd", "unicode"
        ]
        for mut_type in mutation_types:
            fields[field_index] = strategies.mutate_field(original, mut_type)
            segments[target_segment_idx] = "|".join(fields)
            yield {
                "message": "\r".join(segments),
                "rule": rule_name,
                "mutation": mut_type,
                "original_value": original
            }
            fields[field_index] = original
            segments[target_segment_idx] = "|".join(fields)
    
    else:
        # Specific strategy with iterations
        for _ in range(iterations):
            fields[field_index] = strategies.mutate_field(original, strategy)
            segments[target_segment_idx] = "|".join(fields)
            yield {
                "message": "\r".join(segments),
                "rule": rule_name,
                "mutation": strategy,
                "original_value": original
            }
            fields[field_index] = original
            segments[target_segment_idx] = "|".join(fields)


def _generate_segment_mutations(
    base_message: str,
    rule: dict,
    strategies: FuzzingStrategies
) -> Generator[Dict[str, Any], None, None]:
    """Generate segment-level mutations."""
    strategy = rule.get("strategy", "remove")
    rule_name = rule.get("name", "unnamed")
    iterations = rule.get("iterations", 5)
    
    if strategy == "remove":
        for mutated in strategies.remove_segments(base_message):
            yield {
                "message": mutated,
                "rule": rule_name,
                "mutation": "segment_removal",
                "original_value": None
            }
    
    elif strategy == "reorder":
        for mutated in strategies.reorder_segments(base_message, iterations):
            yield {
                "message": mutated,
                "rule": rule_name,
                "mutation": "segment_reorder",
                "original_value": None
            }
    
    elif strategy == "add":
        for mutated in strategies.add_segments(base_message, iterations):
            yield {
                "message": mutated,
                "rule": rule_name,
                "mutation": "segment_add",
                "original_value": None
            }


def _generate_message_mutations(
    base_message: str,
    rule: dict,
    strategies: FuzzingStrategies
) -> Generator[Dict[str, Any], None, None]:
    """Generate message-level mutations."""
    strategy = rule.get("strategy", "delimiter")
    rule_name = rule.get("name", "unnamed")
    
    if strategy == "delimiter":
        for mutated in strategies.mutate_delimiter(base_message):
            yield {
                "message": mutated,
                "rule": rule_name,
                "mutation": "delimiter_mutation",
                "original_value": None
            }


def run_fuzzing_job(
    job_id: str,
    config: dict,
    db_session_factory=None,
    progress_callback=None,
    project_id: str = None,
    authorized: bool = False
) -> Dict[str, Any]:
    """
    Execute a fuzzing job.

    This function runs the fuzzing campaign, sending mutated messages
    to the target and collecting results. It can run standalone or
    with database integration for the web UI.

    Args:
        job_id: Unique identifier for this job
        config: Fuzzing configuration dictionary
        db_session_factory: Optional SQLAlchemy session factory for DB updates
        progress_callback: Optional callback(progress, stats) for progress updates
        project_id: Optional project ID for organizing logs
        authorized: Operator confirmation that a non-loopback target may be
            fuzzed. Loopback targets ignore this; non-loopback targets are
            refused unless it is True (see medaudit.fuzzer.safety).

    Returns:
        Dictionary containing job results:
        - status: Final status ('completed', 'stopped', 'error')
        - total_requests: Number of requests sent
        - successful: Number of successful requests
        - errors: Number of failed requests
        - interesting: Number of interesting findings
        - findings: List of interesting finding details
        - traffic_log_dir: Directory containing traffic logs
        
    Example:
        >>> result = run_fuzzing_job("job-123", config, project_id="proj-456")
        >>> print(f"Found {result['interesting']} interesting cases")
    """
    global _active_jobs
    
    # Initialize job tracking
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
    
    db = None
    traffic_logger = None

    try:
        # --- Safety guardrails: refuse unauthorized non-loopback targets ---
        # Do this before any side effects (traffic logger, DB "running" state).
        target_host = config.get("target_host", "localhost")
        try:
            check_authorization(target_host, authorized)
        except TargetNotAuthorized as e:
            logger.warning("Fuzzing job %s refused: %s", job_id, e)
            _active_jobs[job_id]["status"] = "refused"
            _active_jobs[job_id]["error"] = str(e)
            if db_session_factory:
                try:
                    from medaudit.web.database import FuzzingJob
                    _db = db_session_factory()
                    _job = _db.query(FuzzingJob).filter(FuzzingJob.id == job_id).first()
                    if _job:
                        _job.status = "refused"
                        _db.commit()
                    _db.close()
                except Exception:
                    pass
            return {
                "status": "refused",
                "error": str(e),
                "total_requests": 0,
                "findings": [],
            }

        # Initialize traffic logger
        job_name = config.get("name", f"Job {job_id[:8]}")
        
        if project_id:
            from medaudit.utils.paths import get_fuzzing_job_logs_dir
            log_dir = get_fuzzing_job_logs_dir(project_id, job_id)
            log_base_dir = log_dir.parent
        else:
            from medaudit.utils.paths import get_fuzzing_logs_dir
            log_base_dir = get_fuzzing_logs_dir()
        
        from medaudit.fuzzer.traffic_logger import FuzzingTrafficLogger
        traffic_logger = FuzzingTrafficLogger(log_base_dir, job_id, job_name)
        
        # Update database if available
        if db_session_factory:
            from medaudit.web.database import FuzzingJob
            db = db_session_factory()
            job = db.query(FuzzingJob).filter(FuzzingJob.id == job_id).first()
            if job:
                job.status = "running"
                job.started_at = datetime.utcnow()
                job.traffic_log_dir = str(traffic_logger.log_directory)
                job.detailed_traffic_log = str(traffic_logger.get_detailed_log_path())
                job.findings_log = str(traffic_logger.get_findings_log_path())
                job.summary_log = str(traffic_logger.get_summary_path())
                db.commit()
        
        # Extract config values
        base_message = config.get("base_message", "")
        
        # Normalize line endings: YAML uses \n, HL7 needs \r
        if base_message:
            base_message = base_message.strip()
            base_message = base_message.replace("\r\n", "\r")  # Windows
            base_message = base_message.replace("\n", "\r")     # Unix
            # Replace template placeholders
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            msg_id = f"MSG{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            base_message = base_message.replace("{timestamp}", timestamp)
            base_message = base_message.replace("{msg_id}", msg_id)
        
        rules = config.get("rules", [])
        delay_ms = config.get("delay_ms", 100)
        max_requests = config.get("max_requests", 1000)
        stop_on_error = config.get("stop_on_error", False)
        # target_host already read above for the authorization check.
        target_port = config.get("target_port", 2575)
        use_tls = config.get("use_tls", False)
        timeout = config.get("timeout_seconds", 30)

        # Clamp volume and (for remote targets) send rate to safe bounds.
        max_requests, delay_ms, _limit_notes = apply_limits(max_requests, delay_ms, target_host)

        # Generate messages lazily and stop at max_requests so we never
        # materialize an unbounded list (protects memory on large campaigns).
        messages = list(islice(generate_fuzzed_messages(base_message, rules), max_requests))
        total = len(messages) or 1

        findings = []

        for i, msg_data in enumerate(messages):
            # Check for stop signal
            if _active_jobs.get(job_id, {}).get("should_stop"):
                logger.info(f"Job {job_id} stopped by user")
                break
            
            # Send message
            result = send_hl7_message(
                host=target_host,
                port=target_port,
                message=msg_data["message"],
                use_tls=use_tls,
                timeout=timeout
            )
            
            # Log traffic
            if traffic_logger:
                traffic_logger.log_traffic(
                    request_message=msg_data["message"],
                    response_message=result.get("response"),
                    response_time_ms=result.get("response_time_ms", 0),
                    rule_name=msg_data["rule"],
                    mutation_type=msg_data["mutation"],
                    success=result.get("success", False),
                    is_interesting=result.get("is_interesting", False),
                    finding_type=result.get("finding_type"),
                    error_message=result.get("error"),
                    status_code=result.get("status_code"),
                    original_value=msg_data.get("original_value")
                )
            
            # Update stats
            _active_jobs[job_id]["total_requests"] += 1
            _active_jobs[job_id]["progress"] = int((i + 1) / total * 100)
            
            if result.get("success"):
                _active_jobs[job_id]["successful"] += 1
            else:
                _active_jobs[job_id]["errors"] += 1
                if stop_on_error:
                    logger.info(f"Job {job_id} stopped due to error")
                    break
            
            # Record interesting findings
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
            
            # Progress callback
            if progress_callback:
                progress_callback(
                    _active_jobs[job_id]["progress"],
                    _active_jobs[job_id]
                )
            
            # Delay between requests
            time.sleep(delay_ms / 1000)
        
        # Update final status
        final_status = "completed"
        if _active_jobs.get(job_id, {}).get("should_stop"):
            final_status = "stopped"
        
        _active_jobs[job_id]["status"] = final_status
        
        # Finalize traffic logger
        log_summary = None
        if traffic_logger:
            log_summary = traffic_logger.finalize(final_status)
        
        # Update database
        if db_session_factory and db:
            from medaudit.web.database import FuzzingJob
            job = db.query(FuzzingJob).filter(FuzzingJob.id == job_id).first()
            if job:
                job.status = final_status
                job.completed_at = datetime.utcnow()
                job.progress = 100
                job.total_requests = _active_jobs[job_id]["total_requests"]
                job.successful_requests = _active_jobs[job_id]["successful"]
                job.error_requests = _active_jobs[job_id]["errors"]
                job.interesting_findings = _active_jobs[job_id]["interesting"]
                job.findings = findings
                db.commit()
        
        result_dict = {
            "status": final_status,
            "total_requests": _active_jobs[job_id]["total_requests"],
            "successful": _active_jobs[job_id]["successful"],
            "errors": _active_jobs[job_id]["errors"],
            "interesting": _active_jobs[job_id]["interesting"],
            "findings": findings
        }
        
        if log_summary:
            result_dict["log_summary"] = log_summary
        
        return result_dict
        
    except Exception as e:
        logger.error(f"Fuzzing job {job_id} failed: {e}")
        _active_jobs[job_id]["status"] = "error"
        _active_jobs[job_id]["error"] = str(e)
        
        # Finalize traffic logger on error
        if traffic_logger:
            traffic_logger.finalize("error")
        
        if db_session_factory:
            try:
                from medaudit.web.database import FuzzingJob
                db = db_session_factory()
                job = db.query(FuzzingJob).filter(FuzzingJob.id == job_id).first()
                if job:
                    job.status = "error"
                    db.commit()
            except:
                pass
        
        return {
            "status": "error",
            "error": str(e),
            "total_requests": _active_jobs.get(job_id, {}).get("total_requests", 0),
            "findings": []
        }
    
    finally:
        if db:
            try:
                db.close()
            except:
                pass


def stop_job(job_id: str) -> bool:
    """
    Signal a running job to stop.
    
    Args:
        job_id: ID of the job to stop
        
    Returns:
        True if job was running and stop signal sent
        
    Example:
        >>> if stop_job("job-123"):
        ...     print("Job stop requested")
    """
    if job_id in _active_jobs:
        _active_jobs[job_id]["should_stop"] = True
        return True
    return False


def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    """
    Get the current status of a fuzzing job.
    
    Args:
        job_id: ID of the job
        
    Returns:
        Status dictionary or None if job not found
        
    Example:
        >>> status = get_job_status("job-123")
        >>> if status:
        ...     print(f"Progress: {status['progress']}%")
    """
    return _active_jobs.get(job_id)


def list_active_jobs() -> List[str]:
    """
    Get list of currently active job IDs.
    
    Returns:
        List of job IDs that are currently running
    """
    return [
        job_id for job_id, status in _active_jobs.items()
        if status.get("status") == "running"
    ]
