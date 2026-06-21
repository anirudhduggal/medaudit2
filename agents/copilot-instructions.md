# Medaudit 2.0 — AI Agent Instructions

Medical device security analyzer for HL7/FHIR traffic. Detects encryption status, extracts HL7 v2.x messages, identifies PII exposure using Presidio NLP + regex patterns. Features a full-stack web UI with authentication, project management, HL7 client/fuzzer, traffic analysis with visualization, and PDF/JSON export.

**Quick Reference**: See [CLAUDE.md](CLAUDE.md) for a concise developer quick-start guide with essential commands and project structure.


## Current Status (February 11, 2026)

### Recently Fixed Issues
1. **Server Message Log Display** - Fixed UI polling to properly display received HL7 messages in real-time
   - Removed verbose debug logging that was cluttering message log
   - Added tab-click handler to poll logs immediately when Server tab is shown
   - Fixed status synchronization between database and in-memory server state
   
2. **Proxy State Management** - Fixed HTTP→MLLP proxy state tracking across page refreshes
   - Added socket-based port checking to verify actual running status
   - Added `checkProxyStatus()` function called on page load
   - Proxy state now persists correctly when page is refreshed

3. **Server Status Display** - Fixed display showing "Stopped" when server was actually running
   - Now correctly syncs `live_status` to main `status` field in API response
   - Prevents stale database status from overriding in-memory running state

### Known Limitations & TODO
- Proxy error handling needs improvement for concurrent port checks
- Server status should be persisted to disk for recovery after web server restart
- Consider adding WebSocket for real-time log updates instead of polling

## Agent Responsibilities

This document is intended for AI-assisted development agents (Copilot/Code Assistant) working on the `medaudit` codebase. Agents should follow these rules when editing, testing, or documenting the project:

- **Safety First**: Never output or suggest real patient data. Use synthetic or redacted examples in docs and tests.
- **Use Centralized Paths**: Prefer `medaudit.paths` helpers for any filesystem locations (data, logs, artifacts).
- **Dual-State Handling**: When working on server/proxy code, check both in-memory state and database state before changing statuses.
- **Non-destructive Edits**: Make minimal, focused code changes. Do not reformat unrelated files or change public APIs without explicit user approval.
- **Testing**: Run relevant tests after changes (`pytest tests/<target> -q`) and fix only failures introduced by your edits.
- **Logging and Errors**: Log errors with context, and return safe defaults; do not crash the process on malformed inputs.
- **Documentation**: Update `README.md` and `docs/` whenever behavior or CLI usage changes. Link to this instruction file from the top-level README.
- **Config Precedence**: Respect the configuration override order (CLI args → medaudit/config/medaudit.json → user config locations).

If you need clarification on scope or risk, ask the repository owner before making wide-reaching changes.

## Architecture Overview
```
medaudit/
├── __main__.py                        # CLI dispatcher (analyze|web|proxy|config|fuzzer|user)
├── utils/                             # Utilities and helpers
│   └── paths.py                       # Centralized path management (data, config, logs)
├── analysis/
│   ├── traffic/traffic_analysis.py   # PCAP parsing, encryption heuristics, HL7 extraction
│   └── pii/pii_check.py              # Presidio analyzer + custom recognizers
├── proxy/proxy_server.py             # HTTP→HL7 converter for Burp/ZAP testing
├── hl7server/
│   ├── hl7_mock_server.py            # MLLP-compliant mock server with ACK responses
│   ├── hl7_client.py                 # HL7 client for sending messages
│   ├── message_logger.py             # JSON Lines message logging
│   └── cli.py                        # HL7 server CLI interface
├── fuzzer/                           # Dedicated Medical Device Fuzzer Module
│   ├── __init__.py                   # Module exports
│   ├── __main__.py                   # CLI entry point (python -m medaudit.fuzzer)
│   ├── cli.py                        # Fuzzer CLI commands (run, test, template, validate, server, attacks)
│   ├── strategies.py                 # Mutation strategies (field, segment, delimiter, overflow, injection)
│   ├── engine.py                     # Fuzzing execution engine + message generation
│   ├── protocol.py                   # HL7/MLLP protocol handling
│   ├── templates.py                  # Default fuzzing config templates (YAML/JSON)
│   └── malicious_hl7_server.py       # Malicious HL7 server (17 attack modes)
├── config/                           # Package configuration (inside medaudit)
│   ├── medaudit.json                 # Main configuration file
│   ├── hl7server.json                # HL7 server configuration
│   ├── logging.py                    # Custom logging handlers
│   └── __init__.py                   # Configuration loading
├── data/                             # Runtime data (inside medaudit)
│   ├── medaudit.db                   # SQLite database
│   └── artifacts/                    # Project artifacts (PCAPs, exports)
├── logs/                             # Runtime logs (inside medaudit)
│   └── YYYY-MM-DD/                   # Date-organized JSON Lines logs
├── web/
│   ├── app.py                        # FastAPI main app + page routes
│   ├── auth.py                       # User authentication + registration + session management
│   ├── database.py                   # SQLAlchemy models (User, Project, Analysis, etc.)
│   ├── projects.py                   # Project CRUD API (/api/projects)
│   ├── client_api.py                 # HL7 Client API + malformed payload library
│   ├── fuzzer_api.py                 # HL7 Fuzzer Web API (imports from fuzzer module)
│   ├── traffic_api.py                # PCAP upload + analysis + visualization
│   ├── server_api.py                 # Managed HL7 server instances (with message logging)
│   ├── proxy_api.py                  # HTTP→MLLP proxy management
│   ├── ai_api.py                     # AI Analysis API (OpenAI, Anthropic, local models)
│   ├── analyzer.py                   # Enhanced PCAP analyzer for web UI
│   └── templates/                    # Jinja2 HTML templates
│       ├── index.html                # Landing page
│       ├── login.html                # Login/Register page (tabbed interface)
│       ├── dashboard.html            # Project listing + management
│       └── project.html              # Project detail (Client/Fuzzer/Traffic/Server/AI tabs)
└── testFiles/                        # Sample PCAP files for testing
```

## Essential Commands
```bash
# CLI Analysis
python3 -m medaudit analyze <file.pcap>           # Analyze PCAP for encryption + PII

# Web UI (Full Platform)
python3 -m medaudit web --host 0.0.0.0 --port 8080  # Start web UI (default: http://localhost:8080)

# HTTP→HL7 Proxy (Security Testing)
python3 -m medaudit proxy --port 8080 --hl7-port 2575  # For Burp/ZAP integration

# HL7 Mock Server (Standalone)
python3 -m medaudit.hl7server start --port 2575   # MLLP server with ACK responses

# HL7 Fuzzer (Standalone CLI)
python3 -m medaudit.fuzzer run -c config.yaml -o results.json   # Run fuzzing from config
python3 -m medaudit.fuzzer test --host localhost --port 2575    # Test HL7 server connection
python3 -m medaudit.fuzzer template --format yaml > fuzzer.yaml # Generate config template
python3 -m medaudit.fuzzer validate -c config.yaml              # Validate fuzzing config

# Malicious HL7 Server (Medical Device Robustness Testing)
python3 -m medaudit.fuzzer server --mode no_ack --port 2575     # No ACK response
python3 -m medaudit.fuzzer server --mode broken_ack             # Malformed ACK messages
python3 -m medaudit.fuzzer server --mode flood_ack --flood-count 500  # ACK flood attack
python3 -m medaudit.fuzzer server --mode delayed_ack --delay 30 # Delayed ACK (30s)
python3 -m medaudit.fuzzer server --mode overflow_ack           # Buffer overflow test
python3 -m medaudit.fuzzer server --mode injection_ack          # Injection payloads in ACK
python3 -m medaudit.fuzzer server --mode random                 # Random attack per connection
python3 -m medaudit.fuzzer attacks                              # List all attack modes

# Configuration
python3 -m medaudit config --show                 # Display current config
python3 -m medaudit config --create               # Generate default config file
```

## Web UI Features & API Reference

### Authentication (`/auth/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | User login (username, password) → session cookie |
| `/auth/register` | POST | ★ Self-service registration (username, email, password, full_name) → auto-login |
| `/auth/logout` | POST | End session |
| `/auth/me` | GET | Current user info |
| `/auth/check` | GET | Check authentication status |

**Registration Features:**
- Rate-limited to prevent abuse (same limits as login: 5 attempts per 5 minutes)
- Username and email uniqueness validation
- Password strength requirements (minimum 8 characters)
- PBKDF2-SHA256 password hashing (600,000 iterations)
- Automatic session creation after successful registration
- New users are non-admin by default (is_admin=False)

### Project Management (`/api/projects/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/projects` | GET | List all projects for user |
| `/api/projects` | POST | Create project (name, description, engagement dates) |
| `/api/projects/{id}` | GET | Get project details |
| `/api/projects/{id}` | PUT | Update project |
| `/api/projects/{id}` | DELETE | Delete project + all artifacts |
| `/api/projects/{id}/stats` | GET | Project statistics summary |
| `/api/projects/{id}/duplicate` | POST | Clone project |

### HL7 Client (`/api/client/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/client/payloads` | GET | Malformed payload library (buffer overflow, SQLi, XSS, etc.) |
| `/api/client/templates` | GET | HL7 message templates (ADT, ORM, ORU) |
| `/api/client/send` | POST | Send HL7 message to target server |
| `/api/client/projects/{id}/sessions` | POST | Create client session |
| `/api/client/projects/{id}/sessions` | GET | List sessions |
| `/api/client/projects/{id}/sessions/{sid}/history` | GET | Message history |
| `/api/client/projects/{id}/sessions/{sid}/send` | POST | Send via session |

### HL7 Fuzzer (`/api/fuzzer/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/fuzzer/templates` | GET | Fuzzing rule templates (YAML/JSON) |
| `/api/fuzzer/validate` | POST | Validate fuzzing config |
| `/api/fuzzer/projects/{id}/jobs` | POST | Start fuzzing job |
| `/api/fuzzer/projects/{id}/jobs` | GET | List fuzzing jobs |
| `/api/fuzzer/projects/{id}/jobs/{jid}` | GET | Job details + results |
| `/api/fuzzer/projects/{id}/jobs/{jid}/stop` | POST | Stop running job |
| `/api/fuzzer/projects/{id}/jobs/{jid}` | DELETE | Delete job |

### Traffic Analysis (`/api/traffic/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/traffic/projects/{id}/upload` | POST | Upload + analyze PCAP |
| `/api/traffic/projects/{id}/analyses` | GET | List all analyses |
| `/api/traffic/projects/{id}/analyses/{aid}` | GET | Full analysis results |
| `/api/traffic/projects/{id}/analyses/{aid}/graph` | GET | Network graph (Cytoscape.js) |
| `/api/traffic/projects/{id}/analyses/{aid}/sequence` | GET | Sequence diagram data |
| `/api/traffic/projects/{id}/analyses/{aid}` | DELETE | Delete analysis |
| `/api/traffic/projects/{id}/summary` | GET | Aggregated stats |

### Server Management (`/api/server/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/server/projects/{id}/servers` | POST | Create managed HL7 server |
| `/api/server/projects/{id}/servers` | GET | List servers |
| `/api/server/projects/{id}/servers/{sid}` | GET | Server details |
| `/api/server/projects/{id}/servers/{sid}` | PUT | Update server config |
| `/api/server/projects/{id}/servers/{sid}/start` | POST | Start server |
| `/api/server/projects/{id}/servers/{sid}/stop` | POST | Stop server |
| `/api/server/projects/{id}/servers/{sid}` | DELETE | Delete server |
| `/api/server/projects/{id}/servers/{sid}/logs` | GET | Server message logs |

### Health Check
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Service health status |

## Database Models (SQLite)
```python
# User: Authentication + projects
User(id, username, email, password_hash, full_name, is_admin, is_active)

# Project: Workspace for security audits
Project(id, name, description, owner_id, engagement_start/end, status, settings)

# PcapAnalysis: Traffic analysis results
PcapAnalysis(id, project_id, filename, file_path, results, total_packets, hl7_message_count, pii_count)

# ClientSession: HL7 client interaction history
ClientSession(id, project_id, server_host, server_port, use_tls, messages)

# FuzzingJob: Fuzzer execution + results
FuzzingJob(id, project_id, name, config, status, results, started_at, completed_at)

# ServerInstance: Managed HL7 servers
ServerInstance(id, project_id, name, host, port, use_tls, cert_path, key_path, status)
```

## Malformed Payload Library (Built-in)
The HL7 Client includes pre-built security test payloads:
- **Buffer Overflow**: Long fields, large segments, excessive segment count
- **Format String**: %n, %s, %x attacks in HL7 fields
- **SQL Injection**: Basic SQLi, UNION, stacked queries in PID segment
- **Command Injection**: OS command injection payloads
- **XXE/XML**: XML entity expansion (for XML-based HL7)
- **Delimiter Attacks**: Mutated |, ^, ~ delimiters
- **Encoding Attacks**: Unicode, null bytes, control characters

## Critical Code Patterns

### MLLP Protocol (Required for HL7 Transport)
```python
MLLP_START, MLLP_END = b'\x0b', b'\x1c\x0d'
mllp_wrapped = MLLP_START + hl7_msg.encode() + MLLP_END
# Unwrap: strip \x0b prefix, split on \x1c
```

### Binary Payload Decoding (Always Use)
```python
payload = pkt[Raw].load.decode('utf-8', errors='ignore')  # NEVER omit errors='ignore'
if 'MSH|' in payload:  # Validate before parsing as HL7
```

### PII Detection (HL7 Parsing + NLP)
PII is extracted using two methods:
1. **HL7 PID Segment Parsing** (score: 1.0, preferred for structured data)
2. **Presidio NLP** (fallback for non-standard fields)

```python
# HL7 PID field positions for PII:
# PID-3: Medical Record Number, PID-5: Name, PID-7: DOB
# PID-11: Address, PID-13/14: Phone, PID-19: SSN, PID-20: Driver's License

# MSH-7 timestamp is captured to distinguish same PII at different times
# Deduplication uses (entity_type, value, timestamp) tuple
```

### Encryption Detection Heuristics
- SSL ports (443, 993, 995, 465, 587, 8443) → encrypted
- Payload entropy > 0.8 → likely encrypted (high unique byte ratio)

### Authentication Pattern (Web APIs)
```python
from .auth import require_auth
from .database import get_db, User

@router.get("/protected")
async def protected_endpoint(
    user: User = Depends(require_auth),  # Raises 401 if not authenticated
    db: Session = Depends(get_db)
):
    # Access user.id for ownership checks
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id  # Enforce ownership
    ).first()
```

## Error Handling Pattern (Required)
All modules must log errors and continue gracefully—never crash on bad input:
```python
import logging
logger = logging.getLogger(__name__)

try:
    result = risky_operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    # Return safe default or skip, don't re-raise unless critical
    return None  # or continue processing other items
```
- **PCAP parsing**: Skip malformed packets, log and continue
- **HL7 parsing**: Return partial results if segments are malformed
- **PII detection**: Catch Presidio/Spacy errors, return empty results
- **Network ops**: Use timeouts, log connection failures, return graceful error responses
- **Web APIs**: Return HTTPException with appropriate status codes

## Configuration Precedence
CLI args → `medaudit/config/medaudit.json` → `config/medaudit.json` → `./medaudit.json` → `~/.medaudit.json` → defaults

## Data Storage (Centralized in medaudit Package)
All runtime data is stored inside the medaudit package directory:
- **Database**: `medaudit/data/medaudit.db` (SQLite)
- **PCAP Artifacts**: `medaudit/data/artifacts/projects/{project_id}/pcaps/`
- **Logs**: `medaudit/logs/YYYY-MM-DD/*.jsonl` (JSON Lines format)
- **Configuration**: `medaudit/config/medaudit.json`, `medaudit/config/hl7server.json`

### Path Management (medaudit/paths.py)
All path references use the centralized `medaudit.paths` module:
```python
from medaudit.paths import (
    PACKAGE_DIR,      # medaudit/ package directory
    DATA_DIR,         # medaudit/data/
    CONFIG_DIR,       # medaudit/config/
    LOGS_DIR,         # medaudit/logs/
    DATABASE_PATH,    # medaudit/data/medaudit.db
    get_artifacts_dir,       # Returns medaudit/data/artifacts/
    get_project_pcaps_dir,   # Returns medaudit/data/artifacts/projects/{id}/pcaps/
    get_database_path,       # Returns database path (creates dirs if needed)
    get_config_search_paths, # Returns config file search order
)
```

## Output Limits (Enforced)
- Max 10 HL7 messages displayed per CLI analysis
- Max 20 PII instances reported per CLI analysis
- Web UI: Paginated results with full data available via API

## Testing & Verification

### Run Full Integration Test (Verifies All Functionality)
```bash
python3 tests/test_comprehensive.py      # Tests: imports, config, logging, traffic, PCAP, proxy
python3 tests/test_comprehensive_hl7.py  # Tests: HL7 server startup, client connection, message flow
```

### Component-Specific Tests
```bash
pytest tests/test_pii_check.py -v        # PII detection accuracy
pytest tests/test_hl7_server_client.py   # HL7 server/client integration
python3 tests/analyze_pcap_pii.py        # Manual PCAP→PII pipeline test
```

### Quick Smoke Test (All Systems)
```bash
pytest -q                                # Run all pytest-compatible tests
```

### End-to-End Workflow Test (CLI)
```bash
# Terminal 1: Start HL7 server
python3 -m medaudit.hl7server start --port 2575

# Terminal 2: Start proxy
python3 -m medaudit proxy --port 8080 --hl7-port 2575

# Terminal 3: Send test message
curl -X POST http://localhost:8080/ -d 'MSH|^~\&|TEST|LAB|EHR|HOSP|202601311200||ADT^A01|MSG001|P|2.5'
```

### Web UI Testing
```bash
# Start web server
python3 -m medaudit web --port 8080

# Access UI
open http://localhost:8080

# Default admin account created on first start (check logs for credentials)
# Or register a new account at /register
```

## Real-Time Server State Management (Critical for Web UI)

### Dual-State Pattern (Database + In-Memory)
The web UI manages servers using both persistent and transient state:
- **Persistent**: SQLite database stores server config, status, and message logs
- **Transient**: Python dictionary `_active_servers` tracks running instances in memory

**Why both?** Database survives web server restart; in-memory dict provides instant status updates.

### Message Log Polling (`/api/server/projects/{id}/servers/{sid}/logs`)

**Flow:**
1. UI calls `pollServerLogs()` every 2 seconds when Server tab is visible
2. API endpoint checks if server is in `_active_servers` (in-memory):
   - **If found**: Return `message_log` from active server object + `live_status`
   - **If not found**: Return `message_log` from database + sync stale status if needed

**Code Pattern** (server_api.py):
```python
# When retrieving logs, check both sources
if server_id in _active_servers:
    live_server = _active_servers[server_id]
    live_status = live_server.get("status", "unknown")
    message_log = live_server.get("message_log", [])
    # Return live status + current messages
else:
    # Server not in memory (web server restarted)
    # Return from database, but fix stale "running" status
    if server.status == "running":
        server.status = "stopped"
        db.commit()
    message_log = server.message_log or []
```

**UI Fallback** (project.html):
```javascript
async function pollServerLogs() {
    // Check both live_status and status fields
    const liveStatus = data.live_status || data.status;
    if (liveStatus === 'running' && data.live_message_log) {
        // Use live log from in-memory state
    } else if (data.status === 'running') {
        // Fallback to database messages
    }
}
```

### Server Startup/Shutdown Lifecycle

**Starting a Server** (`run_server()` in server_api.py):
```python
# 1. Add to active dict (immediate UI update)
_active_servers[sid] = {
    "server_obj": server,
    "status": "running",
    "message_log": [],
    "thread": Thread(...)
}

# 2. Start thread with server.start() method
thread.start()

# 3. Finally block (critical fix):
#    ONLY mark as stopped if it was actually running
#    (prevents false "stopped" when normal shutdown occurs)
finally:
    if _active_servers[sid].get("status") == "running":
        _active_servers[sid]["status"] = "stopped"
```

**Stopping a Server** (`stop_server()` API):
```python
# 1. Remove from active dict first
if sid in _active_servers:
    _active_servers[sid]["server_obj"].shutdown()
    del _active_servers[sid]

# 2. Update database to match
server.status = "stopped"
db.commit()
```

### Proxy State Management (Port Availability Checking)

**Problem**: Browser refresh + stale in-memory state causes false "already running" errors

**Solution: Three-Tier Port Checking** (proxy_api.py):
```python
import socket

def is_port_available(port):
    # Tier 1: Check if port actually has a listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    
    if result == 0:
        # Port is in use, socket connected
        return False
    
    # Tier 2: Check if tracked in active_proxies dict
    if port in active_proxies:
        # Verify process is still running
        if not active_proxies[port].is_alive():
            del active_proxies[port]  # Clean up stale entry
    
    return True
```

**UI State Recovery** (project.html - `checkProxyStatus()`):
```javascript
async function checkProxyStatus() {
    const response = await fetch(`/api/proxy/status?proxy_port=${proxyPort}`);
    const data = await response.json();
    
    if (data.success && data.proxy?.status === 'running') {
        // Proxy actually running, update UI buttons
        startProxyBtn.style.display = 'none';
        stopProxyBtn.style.display = 'inline';
    } else {
        // Proxy not running, show start button
        startProxyBtn.style.display = 'inline';
        stopProxyBtn.style.display = 'none';
    }
}

// Call on page load to sync UI with actual server state
document.addEventListener('DOMContentLoaded', () => {
    loadProject();
    checkProxyStatus();  // Recover state after refresh
});
```

### Debugging In-Memory vs Database State Mismatches

**Common Scenario: Web Server Restart**

1. **Before restart**:
   - Server in `_active_servers` with status="running"
   - Database shows status="running"
   - UI shows "Stop" button

2. **Web server restarts**:
   - `_active_servers` dict cleared (process memory lost)
   - Database still shows status="running" (stale)
   - UI queries API, gets stale status from database

3. **Fix: API syncs state**:
   ```python
   # In list_servers() endpoint
   for s in servers:
       if s.id in _active_servers:
           # Server running in memory, trust that status
           s.live_status = _active_servers[s.id].get("status")
           s.status = s.live_status  # Override database
       else:
           # Server not in memory
           if s.status == "running":
               # Database shows running but process is gone
               s.status = "stopped"
               db.commit()
   ```

### Message Log Polling Pitfalls

**❌ WRONG**: Only check database status
```python
# BUG: Will show "No messages" even if server is running
if server.status != "running":
    return {"messages": []}
```

**✓ CORRECT**: Check both live and database status
```python
# CORRECT: Check in-memory first
if server_id in _active_servers:
    return {"messages": _active_servers[server_id]["message_log"]}

# Fallback to database
if server.status == "running":
    return {"messages": server.message_log}
```

## Setup (Post-clone)
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg  # Required for Presidio NLP
```

## Debugging State Synchronization Issues

### Problem Identification Checklist
1. **UI shows wrong status after refresh** → Check `_active_servers` vs database state mismatch
2. **Messages not showing in Server tab** → Verify polling hits both `live_message_log` and database log
3. **Proxy "already running" error on refresh** → Check if `active_proxies` dict has stale entries
4. **Server shows "Stopped" when actively running** → Check if `finally` block is running unconditionally

### Tools for Debugging

**Check In-Memory Server State**:
```python
from medaudit.web.server_api import _active_servers

# During debugging: inspect what's actually in memory
print(_active_servers)  # Shows all running servers
print(_active_servers.get(server_id, {}).get("status"))  # Check live status
```

**Check Database Status**:
```python
from medaudit.web.database import get_db, ServerInstance

db = next(get_db())
server = db.query(ServerInstance).get(server_id)
print(f"DB Status: {server.status}")  # Compare with live status
```

**Verify Port Availability**:
```python
import socket

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0  # True if port in use
```

**Check Message Log Size**:
```javascript
// In browser console, verify messages are being collected
fetch('/api/server/projects/1/servers/1/logs')
    .then(r => r.json())
    .then(d => console.log('Messages:', d.live_message_log?.length || 0))
```

### Common Fix Patterns

**Pattern 1: Add Dual-State Checking**
```python
# Before: Only checked one source
if server.status != "running":
    return error()

# After: Check both sources
if server.id in _active_servers or server.status == "running":
    # Handle as running
```

**Pattern 2: Add Status Sync on Restart Detection**
```python
# Before: Assumed database was always accurate
# After: Detect if server was removed from memory
if server_id not in _active_servers and server.status == "running":
    server.status = "stopped"
    db.commit()
```

**Pattern 3: Add Socket Verification Before Using Stale Tracking**
```python
# Before: Trusted in-memory dict only
if port in active_proxies:
    raise "Already running"

# After: Verify port actually in use
if is_port_in_use(port):
    if port in active_proxies:
        # Track is correct
    else:
        # Stale process, clean up dict
        del active_proxies[port]
```

## Key Constraints
1. Never hardcode config values—use `config.get_proxy_config()` etc.
2. Always validate `MSH|` marker before treating data as HL7
3. MLLP framing is mandatory for HL7 device communication
4. Presidio analyzer uses Spacy `en_core_web_lg`—slow to initialize, cache it
5. Log all errors with context, never let exceptions crash the program
6. All web API endpoints require authentication (except /auth/login, /auth/register)
7. Project ownership is enforced—users can only access their own projects
8. Use `require_auth` dependency for protected endpoints
9. Database sessions managed via `get_db` dependency injection
10. **CRITICAL**: Always use dual-state checking for servers/proxies (in-memory + database)
11. **CRITICAL**: Never rely solely on in-memory dicts across web server restarts
12. **CRITICAL**: Socket connectivity checks are more reliable than process tracking
