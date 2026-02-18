# Medaudit 2.0 - Medical Device Security Audit Platform

A comprehensive security auditing tool for HL7 v2.x medical device communications. Built for penetration testers, security auditors, and researchers working with healthcare systems.

Medaudit provides PCAP traffic analysis, PII detection, an interactive HL7 client with malformed payload library, protocol fuzzing, a managed HL7 server, HTTP-to-HL7 proxying, and an AI-powered pentest co-pilot -- all through a unified web interface.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/anirudhduggal/medaudit2.git
cd medaudit2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Download Spacy model for PII detection (one-time, ~500MB)
python -m spacy download en_core_web_lg

# Start the web UI
python -m medaudit web --generate-password
```

Open `http://localhost:8080` and log in with the credentials shown in the terminal.

---

## Features

### Web UI Platform

The primary interface for security auditing. Start with `python -m medaudit web` and access all features through the browser.

**Authentication & Projects**
- Single local admin account with CLI-configurable password (`--password` or `--generate-password`)
- PBKDF2-SHA256 password hashing, rate-limited login (5 attempts / 5 min), session management
- Project-based workspace organization for managing multiple engagements
- Security headers (CSP, X-Frame-Options, etc.) on all responses

**Client Tab -- Manual Testing**
- Interactive HL7 client for sending messages to medical devices
- Built-in malformed payload library: buffer overflow, SQL injection, XXE, command injection, format strings, delimiter manipulation
- **Send Mode selector**: send payloads as a client (to a server) or start a malicious server (to send crafted responses to connecting clients)
- HL7 Listener (Proxy) for receiving messages from medical devices
- Full request/response logging

**Fuzzer Tab -- Automated Testing**
- YAML/JSON fuzzing rule configuration
- Strategies: field mutation (overflow, special chars, SQL, cmd injection, unicode, boundary), segment injection/removal/reorder, delimiter manipulation
- Real-time progress, start/stop controls, finding detection
- Automatically uses target configured in the Client tab

**Traffic Tab -- PCAP Analysis**
- Upload and analyze PCAP files with HL7 traffic
- HL7 message parsing with segment-level field detail
- PII detection (Presidio NLP + regex): names, patient IDs, SSNs, credit cards, phone numbers, addresses
- Encryption status assessment
- Network flow visualization (Cytoscape.js graph + sequence diagrams)
- Connection table with protocol and encryption breakdown

**Server Tab -- Managed HL7 Servers**
- Create multiple HL7 server instances with configurable ports
- TLS support with certificate path validation
- Real-time message logging (connections, received messages, sent ACKs, errors)
- Start/stop with clean port release

**AI Pentest Assistant (Sidebar)**
- Persistent sidebar accessible across all tabs
- AI-powered analysis with full project context awareness (server logs, client history, fuzzer findings, PCAP results)
- Actionable suggestions with executable "Run this" buttons
- Auto-analysis of events with batched processing
- Token usage and cost tracking
- Quick prompts: Status overview, Vulnerability analysis, Next steps

### AI Provider Support

Configure AI providers globally in **Settings** (gear icon on dashboard). All configured providers are available in every project's sidebar.

| Provider | Models | Setup |
|----------|--------|-------|
| **Anthropic Claude** | Claude Sonnet 4, Claude 3.5 Sonnet/Haiku, Claude 3 Opus | API key from [console.anthropic.com](https://console.anthropic.com/settings/keys) |
| **OpenAI** | GPT-4o, GPT-4o Mini, GPT-4 Turbo, o1, o3-mini | API key from [platform.openai.com](https://platform.openai.com/api-keys) |
| **Google Gemini** | Gemini 2.5 Flash/Pro, Gemini 2.0 Flash, Gemini 1.5 Pro/Flash | API key from [aistudio.google.com](https://aistudio.google.com/apikey) |
| **Ollama (Local)** | Any locally installed model | [ollama.com](https://ollama.com) -- no API key needed |

API keys are stored in-memory only (never persisted to disk) and can be wiped via the Disconnect button or by restarting the server.

### CLI Tools

In addition to the web UI, Medaudit provides standalone CLI commands:

```bash
# Analyze a PCAP file
python -m medaudit analyze path/to/capture.pcap

# Start HL7 mock server
python -m medaudit.hl7server start --port 2575

# Start HTTP-to-HL7 proxy (for Burp Suite / ZAP integration)
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575

# Show/create configuration
python -m medaudit config --show
python -m medaudit config --create
```

---

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `web` | Start web UI | `python -m medaudit web --generate-password --port 8080` |
| `analyze` | Analyze PCAP file | `python -m medaudit analyze capture.pcap` |
| `proxy` | HTTP-to-HL7 proxy | `python -m medaudit proxy --port 8080 --hl7-port 2575` |
| `config` | Manage configuration | `python -m medaudit config --show` |
| `hl7server start` | Start HL7 server | `python -m medaudit.hl7server start --port 2575` |

### Web Server Options

```bash
python -m medaudit web [OPTIONS]

Options:
  --host TEXT          Host to bind (default: 0.0.0.0)
  --port INT           Port to listen on (default: 8080)
  --password TEXT      Set a custom admin password
  --generate-password  Generate a random secure password
```

---

## Configuration

Configuration files are auto-loaded from `medaudit/config/medaudit.json`:

```json
{
  "proxy": {
    "http_host": "0.0.0.0",
    "http_port": 8080,
    "hl7_host": "localhost",
    "hl7_port": 2575
  },
  "analysis": {
    "max_hl7_messages": 10,
    "max_pii_instances": 20
  },
  "logging": {
    "enabled": true,
    "log_dir": "logs"
  }
}
```

### Data Storage

All runtime data is stored inside the `medaudit/` package:
- **Database**: `medaudit/data/medaudit.db` (SQLite)
- **Project artifacts**: `medaudit/data/artifacts/projects/<project_id>/pcaps/`
- **Logs**: `medaudit/logs/YYYY-MM-DD/`
- **Configuration**: `medaudit/config/`

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Specific test file
pytest tests/test_pii_check.py -v

# With coverage
pytest tests/ --cov=medaudit --cov-report=html
```

---

## Security

Medaudit implements the following security measures:

- **Password hashing**: PBKDF2-SHA256 with 600,000 iterations and constant-time comparison
- **No default password**: Generates a random 20-character password if none is specified
- **Rate limiting**: 5 login attempts per 5 minutes, 15-minute lockout
- **Session management**: httpOnly cookies, 24-hour expiry, server-side revocation on logout
- **Security headers**: X-Content-Type-Options, X-Frame-Options, CSP, Permissions-Policy
- **Path traversal protection**: TLS certificate paths validated against allowlist
- **API key safety**: Stored in-memory only, never written to disk or database

---

## Troubleshooting

**Spacy model not found:**
```bash
python -m spacy download en_core_web_lg --upgrade
```

**Port already in use:**
```bash
lsof -i :8080
kill -9 <PID>
```

**Database schema mismatch after update:**
```bash
rm medaudit/data/medaudit.db
# Restart the server -- database will be recreated
```

**Import errors:**
```bash
source venv/bin/activate
pip install --force-reinstall -r requirements.txt
```

---

## Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/anirudhduggal">
        <img src="https://github.com/anirudhduggal.png" width="80px;" alt="anirudhduggal"/><br />
        <sub><b>anirudhduggal</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/securient">
        <img src="https://github.com/securient.png" width="80px;" alt="securient"/><br />
        <sub><b>securient</b></sub>
      </a>
    </td>
  </tr>
</table>

---

## Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Follow existing code patterns and PEP 8 style
4. Add tests for new functionality
5. Submit a pull request

---

## Disclaimer

**Medaudit 2.0 is intended for authorized security testing and research purposes only.**

- Use only on systems you have explicit permission to test
- The authors are not responsible for any misuse or damage caused by this tool
- Always comply with applicable laws, regulations, and organizational policies
- Medical device testing should follow proper regulatory guidelines (FDA, IEC 62443)

---

## License

MIT License -- see [LICENSE](LICENSE) for details.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/anirudhduggal/medaudit2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/anirudhduggal/medaudit2/discussions)
