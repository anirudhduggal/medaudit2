# Fuzzing Traffic Logs - Quick Start Guide

## What Are Fuzzing Logs?

When you run a fuzzing job in Medaudit, ALL traffic is automatically logged:
- **Every request sent** to the target device
- **Every response received** from the device
- **Metadata** about each request (timing, success/failure)
- **Findings** for interesting cases (crashes, unusual responses)

Logs are organized by project and job, ready for download anytime.

## Where Are Logs Stored?

```
medaudit/data/fuzzing_logs/
├── your-project-id/
│   └── job-id/
│       ├── traffic_detailed.jsonl    ← All traffic (streaming)
│       ├── findings.jsonl             ← Interesting cases only
│       ├── traffic_summary.json       ← Statistics summary
│       └── metadata.json              ← Real-time updates
```

## How to Download Logs

### Via Web UI (Easiest)

1. **Go to your Project** → **Fuzzer Tab**
2. Scroll down to **"Fuzzing Test History & Logs"** section
3. Find your fuzzing job in the table
4. Click **"Logs"** button
5. A modal appears with download links:
   - **Detailed Traffic Log** - All requests/responses (JSON Lines)
   - **Findings Log** - Interesting findings only (JSON Lines)  
   - **Summary Report** - Job statistics (JSON)
6. Click to download

### Via API (Command line)

```bash
# Get log information
curl "http://localhost:8080/api/fuzzer/projects/<project-id>/jobs/<job-id>/logs/summary"

# Download detailed traffic
curl -O "http://localhost:8080/api/fuzzer/projects/<project-id>/jobs/<job-id>/logs/download/detailed"

# Download findings
curl -O "http://localhost:8080/api/fuzzer/projects/<project-id>/jobs/<job-id>/logs/download/findings"

# Download summary
curl -O "http://localhost:8080/api/fuzzer/projects/<project-id>/jobs/<job-id>/logs/download/summary"
```

## Understanding Log Files

### 1. traffic_detailed.jsonl (Complete Audit)

**Format:** JSON Lines (one JSON object per line)

**What it contains:** Every single request and response

**Example entry:**
```json
{
  "timestamp": "2026-02-11T15:30:45.123456",
  "sequence_number": 1,
  "rule_name": "pid_field_overflow",
  "mutation_type": "buffer_overflow",
  "original_value": "SMITH^JOHN",
  "request_message": "MSH|^~\\&|MEDAUDIT|...\nPID|1||123456||TEST^USER||...",
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

**Use for:**
- Complete audit trail
- Compliance documentation
- Detailed analysis
- Replay testing specific requests
- Performance analysis

### 2. findings.jsonl (Interesting Cases)

**Format:** JSON Lines (subset of traffic_detailed.jsonl)

**What it contains:** Only entries marked as "interesting" (potential issues)

**Example:**
```json
{
  "timestamp": "2026-02-11T15:31:50.789",
  "sequence_number": 42,
  "rule_name": "message_overflow",
  "mutation_type": "overflow",
  "request_message": "MSH|^~\\&|...",
  "response_time_ms": 2345.67,
  "success": true,
  "is_interesting": true,
  "finding_type": "delayed_response",
  "details": {
    "request_preview": "MSH|^~\\&|MEDAUDIT|...",
    "response_preview": "MSH|^~\\&|DEVICE|..."
  }
}
```

**Use for:**
- Quick review of potential vulnerabilities
- Prioritize further investigation
- Export to issue tracking systems
- Create detailed security reports

### 3. traffic_summary.json (Statistics)

**Format:** Formatted JSON (single file)

**What it contains:** High-level job overview and statistics

**Example:**
```json
{
  "job_id": "job-abc123def456",
  "job_name": "PID Segment Fuzzing - Feb 11",
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
  }
}
```

**Use for:**
- Executive summaries
- Performance trending
- Dashboard displays
- Quick status checks

## Processing Logs

### Python: Load and Analyze
```python
import json

# Load all traffic
with open('traffic_detailed_job-456.jsonl') as f:
    traffic = [json.loads(line) for line in f]

print(f"Total requests: {len(traffic)}")
print(f"Success rate: {sum(1 for t in traffic if t['success']) / len(traffic) * 100:.1f}%")

# Find slow responses
slow = [t for t in traffic if t['response_time_ms'] > 100]
print(f"Slow responses (>100ms): {len(slow)}")

# Analyze findings
with open('findings_job-456.jsonl') as f:
    findings = [json.loads(line) for line in f]

for f in findings:
    print(f"[{f['finding_type']}] {f['rule_name']}: {f['response_time_ms']}ms")
```

### JavaScript: Process in Browser
```javascript
// Fetch and parse findings
async function analyzeFuzzing() {
  const response = await fetch(
    '/api/fuzzer/projects/proj-123/jobs/job-456/logs/download/findings'
  );
  const text = await response.text();
  
  const findings = text
    .trim()
    .split('\n')
    .filter(line => line)
    .map(line => JSON.parse(line));
  
  // Group by finding type
  const byType = {};
  findings.forEach(f => {
    byType[f.finding_type] = (byType[f.finding_type] || 0) + 1;
  });
  
  console.table(byType);
}
```

### Shell: Quick Stats
```bash
# Count total lines (requests)
wc -l traffic_detailed_job-456.jsonl

# Count interesting findings
wc -l findings_job-456.jsonl

# Find slowest response
cat traffic_detailed_job-456.jsonl | \
  jq '.response_time_ms' | \
  sort -rn | head -1

# Extract all error messages
cat traffic_detailed_job-456.jsonl | \
  jq -r 'select(.error_message) | .error_message' | \
  sort | uniq -c | sort -rn
```

## Log Statistics Example

From a typical fuzzing run:

```
Job: PID Segment Fuzzing - Feb 11
Duration: 5 minutes 30 seconds
Total Requests Sent: 500
Successful Responses: 495 (99%)
Failed Requests: 5 (1%)
Interesting Findings: 3

Response Times:
  Average: 32.5ms
  Minimum: 10.2ms
  Maximum: 120.5ms

Traffic:
  Sent: 156 KB
  Received: 92 KB

Findings:
  1 crash (unresponsive)
  1 delayed response (2.3 seconds)
  1 invalid response format
```

## Common Use Cases

### 1. Vulnerability Investigation
```bash
# Get details of a specific finding
cat findings_job-456.jsonl | \
  jq 'select(.finding_type == "crash")'
```

### 2. Performance Baseline
```bash
# Create performance report
cat traffic_detailed_job-456.jsonl | \
  jq '{
    avg: [.response_time_ms] | add / length,
    p50: [.response_time_ms] | sort | .[length/2],
    p95: [.response_time_ms] | sort | .[(length*0.95)]
  }'
```

### 3. Compliance Documentation
- Download summary report
- Import into security testing document
- Timestamp proves when testing occurred
- Results show device behavior under fuzzing

### 4. Regression Testing
```bash
# Compare two fuzzing runs
# Run 1 baseline: baseline_job-123.jsonl
# Run 2 regression: current_job-456.jsonl

# Check if response times degraded
baseline_avg=$(cat baseline_job-123.jsonl | \
  jq '[.response_time_ms] | add / length')
current_avg=$(cat current_job-456.jsonl | \
  jq '[.response_time_ms] | add / length')
  
echo "Baseline avg: ${baseline_avg}ms"
echo "Current avg: ${current_avg}ms"
```

### 5. Export to Excel/CSV
```python
import json
import csv

with open('traffic_detailed_job-456.jsonl') as f, \
     open('traffic.csv', 'w', newline='') as out:
    writer = csv.DictWriter(out, fieldnames=[
        'timestamp', 'sequence_number', 'rule_name',
        'response_time_ms', 'success', 'is_interesting'
    ])
    writer.writeheader()
    
    for line in f:
        entry = json.loads(line)
        writer.writerow({
            'timestamp': entry['timestamp'],
            'sequence_number': entry['sequence_number'],
            'rule_name': entry['rule_name'],
            'response_time_ms': entry['response_time_ms'],
            'success': entry['success'],
            'is_interesting': entry['is_interesting']
        })

print("Exported to traffic.csv")
```

## Tips & Tricks

### Large Log Files
- Use JSON Lines format (stream processing, no memory issues)
- Process line-by-line with `jq`, `python`, or `javascript`
- Don't load entire file into memory

### Quick Filtering
```bash
# Get only failed requests
cat traffic.jsonl | jq -r 'select(.success == false)'

# Get only slow responses (>100ms)
cat traffic.jsonl | jq 'select(.response_time_ms > 100)'

# Count by rule
cat traffic.jsonl | jq '.rule_name' | sort | uniq -c | sort -rn
```

### Log Retention
- Logs stay with project
- Delete project → deletes logs
- Backup important logs before deletion
- No automatic cleanup (logs are persistent)

## Troubleshooting

**Q: Can't find logs?**
- Job must be completed (or running) to have logs
- Check "Fuzzing Test History & Logs" section
- May take a few seconds to appear after job starts

**Q: Downloaded file won't open?**
- Detailed and Findings logs are JSON Lines (each line is valid JSON)
- Open with text editor to inspect individual lines
- Use `jq` command-line tool for processing
- Use Python script to parse and analyze

**Q: Log file is too large?**
- Normal for large fuzzing runs (1000+ requests)
- Use JSON Lines format advantage: stream processing
- Process line-by-line instead of loading entire file

**Q: Can I delete logs?**
- Logs are tied to fuzzing job
- Deleting job also deletes logs
- Backup important logs first!

## Contact & Support

For issues with fuzzing logs:
1. Check documentation in `/docs/FUZZING_TRAFFIC_LOGGING_GUIDE.md`
2. Review logs directory structure
3. Verify login and project access
4. Check API responses for error messages
