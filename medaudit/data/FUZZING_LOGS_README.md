# Fuzzing Traffic Logs

All fuzzing jobs generate comprehensive traffic logs stored in project-specific directories for organization and easy access.

## Directory Structure

```
medaudit/data/
├── fuzzing_logs/                          # Base fuzzing logs directory
│   └── projects/
│       └── {project_id}/                  # Project-specific fuzzing logs
│           └── {job_id}/                  # Job-specific logs directory
│               ├── traffic_detailed.jsonl # Complete request/response log (JSON Lines)
│               ├── findings.jsonl         # Interesting findings only (JSON Lines)
│               ├── traffic_summary.json   # Summary statistics and metadata
│               └── metadata.json          # Real-time metadata updates
```

## Log Files Explained

### 1. traffic_detailed.jsonl
**Complete audit trail of all fuzzing traffic**

This is a JSON Lines file (one JSON object per line) containing every request and response.

**Fields per entry:**
```json
{
  "timestamp": "2026-02-11T15:30:45.123456",
  "sequence_number": 1,
  "rule_name": "field_mutation_pid5",
  "mutation_type": "buffer_overflow",
  "original_value": "SMITH^JOHN",
  "request_message": "MSH|^~\\&|...\nPID|1||...",
  "request_length": 245,
  "response_message": "MSH|^~\\&|...\nMSA|AA|MSG001",
  "response_length": 89,
  "response_time_ms": 45.32,
  "success": true,
  "is_interesting": false,
  "finding_type": null,
  "error_message": null,
  "status_code": "AA"
}
```

**Use cases:**
- Complete audit trail for compliance reports
- Detailed analysis of each mutation and response
- Replay testing specific requests
- Performance analysis (response times)

### 2. findings.jsonl
**Interesting findings and anomalies**

A filtered JSON Lines file containing only entries marked as interesting (potential vulnerabilities, crashes, unexpected behavior).

**Same structure as traffic_detailed.jsonl with additional finding details**

**Use cases:**
- Quick review of potential security issues
- Prioritize further investigation
- Create detailed vulnerability reports
- Export for remediation tracking

### 3. traffic_summary.json
**Job summary and statistics**

A single JSON file with high-level overview and aggregated statistics.

**Content:**
```json
{
  "job_id": "job-abc123def456",
  "job_name": "PID Segment Fuzzing",
  "start_time": "2026-02-11T15:30:00.000000",
  "end_time": "2026-02-11T15:35:30.000000",
  "final_status": "completed",
  "statistics": {
    "total_requests": 500,
    "successful_responses": 495,
    "failed_responses": 5,
    "interesting_findings": 3,
    "total_bytes_sent": 156234,
    "total_bytes_received": 92400,
    "average_response_time_ms": 32.5,
    "min_response_time_ms": 10.2,
    "max_response_time_ms": 120.5
  },
  "log_files": {
    "detailed_traffic": "traffic_detailed.jsonl",
    "findings": "findings.jsonl",
    "metadata": "metadata.json"
  },
  "directory": "/path/to/medaudit/data/fuzzing_logs/proj-123/job-456"
}
```

**Use cases:**
- Quick overview of job performance
- Process monitoring dashboards
- Performance trending
- Executive summaries

### 4. metadata.json
**Real-time metadata and progress tracking**

Updated periodically during job execution and when job completes.

**Content:**
```json
{
  "job_id": "job-abc123def456",
  "job_name": "PID Segment Fuzzing",
  "start_time": "2026-02-11T15:30:00.000000",
  "last_updated": "2026-02-11T15:30:45.000000",
  "statistics": {
    "total_requests": 125,
    "successful_responses": 123,
    "failed_responses": 2,
    "interesting_findings": 1,
    "total_bytes_sent": 39063,
    "total_bytes_received": 23100,
    "average_response_time_ms": 32.1,
    "min_response_time_ms": 10.2,
    "max_response_time_ms": 89.3
  }
}
```

## Web API Access

### Download Log Files

**Get log file information:**
```bash
GET /api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/summary
```

**Download detailed traffic log:**
```bash
GET /api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/download/detailed
```

**Download findings log:**
```bash
GET /api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/download/findings
```

**Download summary report:**
```bash
GET /api/fuzzer/projects/{project_id}/jobs/{job_id}/logs/download/summary
```

## Data Management

### Log Retention
- Logs are stored indefinitely in project directories
- Logs tied to project lifecycle (deleted when project deleted)
- Backup logs regularly for compliance

### Organization
- Each project has its own fuzzing logs directory
- Each job creates a separate directory
- Easy to organize by date/project/phase

### Performance Considerations
- JSON Lines format for streaming processing
- Organize by project_id for quick access
- Batch read findings for bulk operations

## Integration with Database

The FuzzingJob model tracks log locations:
- `traffic_log_dir`: Base directory for this job's logs
- `detailed_traffic_log`: Path to traffic_detailed.jsonl
- `findings_log`: Path to findings.jsonl
- `summary_log`: Path to traffic_summary.json

All paths are stored in the database for:
- Easy retrieval and download
- Cleanup operations
- Archive operations

## Accessing Logs Programmatically

### Python Example

```python
from pathlib import Path
import json

# Load detailed traffic log
job_log_dir = Path("/path/to/medaudit/data/fuzzing_logs/proj-123/job-456")
traffic_log = job_log_dir / "traffic_detailed.jsonl"

successful_requests = []
with open(traffic_log) as f:
    for line in f:
        entry = json.loads(line)
        if entry["success"]:
            successful_requests.append(entry)

print(f"Successful requests: {len(successful_requests)}")

# Load findings
findings_log = job_log_dir / "findings.jsonl"
findings = [json.loads(line) for line in open(findings_log)]
print(f"Interesting findings: {len(findings)}")

# Load summary
summary = json.load(open(job_log_dir / "traffic_summary.json"))
print(f"Duration: {summary['statistics']['average_response_time_ms']}ms avg")
```

### JavaScript Example (from Web UI)

```javascript
// Fetch log info
const logSummary = await fetch(
  `/api/fuzzer/projects/${projectId}/jobs/${jobId}/logs/summary`
).then(r => r.json());

// Download detailed traffic log
window.location.href = logSummary.available_logs.detailed_traffic_log.download_url;

// Process findings in UI
const findingsUrl = logSummary.available_logs.findings_log.download_url;
fetch(findingsUrl)
  .then(r => r.text())
  .then(text => {
    const findings = text
      .trim()
      .split('\n')
      .map(line => JSON.parse(line));
    console.log(`Found ${findings.length} interesting cases`);
  });
```

## Compliance & Audit

Logs provide:
- Complete audit trail of all testing activities
- Timestamps for every action
- Success/failure records
- Findings trackedby timestamp
- Device responses for analysis

Perfect for:
- Regulatory compliance documentation
- Security testing reports
- Incident investigation
- Trend analysis over time

## Troubleshooting

**Logs not generating:**
1. Check job status in fuzzer_api
2. Verify project directory exists
3. Check file permissions on data directory
4. Review server logs for errors

**Logs not ingesting properly:**
1. Verify JSON Lines format (one JSON per line)
2. Ensure UTF-8 encoding
3. Check for very long message fields
4. Verify paths saved in database match actual files

**Performance issues with large logs:**
1. Stream process findings.jsonl instead of loading all
2. Use database queries for aggregates
3. Archive old logs to separate storage
