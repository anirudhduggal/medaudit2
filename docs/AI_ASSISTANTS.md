# AI Assistants Guide for Medaudit 2.0

This guide documents all AI assistant configuration files and how they're used by different AI platforms to assist with Medaudit development.

---

## Overview of Configuration Files

| File | Platform | Purpose | Audience |
|------|----------|---------|----------|
| `.cursorrules` | [Cursor IDE](https://cursor.com) | Cursor's built-in code assistant rules | Developers using Cursor IDE |
| `.windsurfrules` | [Windsurf](https://www.codeium.com) | Windsurf's AI-assisted code editor rules | Developers using Windsurf |
| `.geminirules` | [Google Gemini](https://ai.google.dev) | Detailed context for Gemini (via Claude API interface or direct) | Developers asking Gemini questions about code |
| `llms.txt` | General LLMs | Generic instructions for any LLM (Claude, GPT-4, etc.) | Chat interfaces, generic AI assistance |
| `copilot-instructions.md` | GitHub Copilot | Copilot's detailed project instructions | Developers using VS Code with Copilot |

---

## When Each File Is Used

### Cursor IDE (`.cursorrules`)
- **Triggered**: Automatically when working in Cursor IDE
- **Scope**: Code editing, completions, chat within IDE
- **Size**: Concise (~200 lines), focused on coding patterns
- **Content**: Core patterns, file structure, testing requirements

### Windsurf (``.windsurfrules`)
- **Triggered**: Automatically when working in Windsurf
- **Scope**: Code navigation, AI suggestions, IDE chat
- **Size**: Medium (~150 lines), practical workflows
- **Content**: Quick start, common tasks, design principles, common pitfalls

### Google Gemini (`.geminirules`)
- **Triggered**: When pasting into Gemini chat or using API
- **Scope**: Conversational assistance, deep explanations
- **Size**: Comprehensive (~450 lines), rich context
- **Content**: Architecture, patterns, troubleshooting, security context, Gemini-specific guidance
- **Special**: Instructions on **when to verify assumptions** and **dual-state awareness**

### Generic LLMs (`llms.txt`)
- **Triggered**: Via LLMs.txt standard (used by some AI platforms)
- **Scope**: Any Claude, GPT-4, Gemini instance
- **Size**: Medium (~120 lines), high-level
- **Content**: Architecture, patterns, critical concepts, dependencies

### GitHub Copilot (`copilot-instructions.md`)
- **Triggered**: Automatically via `.github/` directory in VS Code
- **Scope**: Code completions, inline suggestions, Copilot chat
- **Size**: Largest (~680 lines), most detailed
- **Content**: Status, architecture, agent responsibilities, web APIs, database models, real-time server management patterns, debugging guides

---

## Key Information Across All Files

### Architecture (All Files)
All files document that Medaudit has these core components:
- **PCAP Analysis** → Encryption detection + HL7 extraction
- **PII Detection** → Presidio NLP + regex hybrid
- **Web UI** → FastAPI with project management
- **HTTP→HL7 Proxy** → Burp/ZAP integration
- **Mock HL7 Server** → MLLP-compliant for testing
- **HL7 Fuzzer** → Message mutation + attack simulation

### Critical Patterns (Emphasized Everywhere)
1. **Binary Payload Decoding**: Always use `errors='ignore'`
2. **HL7 Validation**: Check for `MSH|` marker before parsing
3. **MLLP Framing**: `\x0b` start + `\x1c\r` end (no encryption!)
4. **Presidio Caching**: Initialize once, reuse globally
5. **Configuration Precedence**: CLI → config files → defaults

### Testing Requirements (All Files)
```bash
pytest tests/test_pii_check.py -v                    # PII detection
pytest tests/test_hl7_server_client.py -v           # HL7 integration
python3 tests/analyze_pcap_pii.py                   # Manual PCAP test
```

---

## Detailed Content Comparison

### Cursor Rules (`.cursorrules`)
**Focus**: Coding standards and quick reference

**Includes**:
- Core patterns for HL7, PII, encryption
- Output limits (10 HL7 msgs, 20 PII instances)
- Testing requirements
- File structure reference
- Common code patterns with snippets

**Omits**:
- Web UI details
- Server state management
- Troubleshooting
- Medical device context

### Windsurf Rules (`.windsurfrules`)
**Focus**: Developer workflows and pragmatic guidance

**Includes**:
- Quick navigation with commands
- Key file locations (table)
- Design principles (modular, security-focused)
- Full PCAP analysis pipeline (flowchart)
- Proxy workflow (detailed steps)
- Common pitfalls (❌ list with explanations)
- File structure (tree format)
- Output constraints

**Unique Features**:
- Flowchart-style pipeline documentation
- Pragmatic warnings about crash scenarios
- Developer experience emphasis

### Gemini Rules (`.geminirules`)
**Focus**: Comprehensive context for conversational AI

**Includes**:
- Everything from Cursor + Windsurf
- HL7 protocol details (format, fields, segments)
- MLLP protocol deep dive
- PII detection strategy (dual-mode: structured + NLP)
- Deduplication logic
- File locations for common tasks (table)
- Extended troubleshooting guide
- Binary payload examples
- HL7 parsing code examples
- Configuration loading with precedence
- Detailed gotchas (DO/DON'T lists)
- Medical device security context (regulatory, examples)
- **Gemini-specific guidance**: When to verify, dual-state awareness, binary safety, cache awareness

**Largest & Most Detailed**: 450+ lines with code examples, tables, and step-by-step guidance

### General LLMs (`llms.txt`)
**Focus**: Portable, high-level context

**Includes**:
- Quick start with bash commands
- Architecture overview
- Critical patterns for HL7, encryption, PII
- Configuration precedence (5-level list)
- File locations
- Common tasks (edit sections)
- Dependencies & versions
- Output constraints
- Medical device context

**Portable**: No tool-specific instructions; works with any LLM conversation

### Copilot Instructions (`copilot-instructions.md`)
**Focus**: Comprehensive agent responsibilities and architectural patterns

**Includes**:
- Current status (Feb 11, 2026)
- Recently fixed issues (server logs, proxy state, status display)
- **Agent Responsibilities**: Safety, paths, dual-state handling, non-destructive edits, testing, logging, documentation, config precedence
- Full architecture with detailed components
- Essential commands (comprehensive)
- Web UI API reference (complete endpoint table)
- Database models (SQLAlchemy)
- Malformed payload library reference
- **Critical Code Patterns**: MLLP, binary decoding, PII detection, encryption heuristics, auth pattern, error handling
- **Real-Time Server State Management**: Dual-state pattern, message log polling, proxy state, startup/shutdown lifecycle, debugging guide
- Key constraints (10 items, detailed)
- Testing & verification (multiple test levels)
- Setup instructions

**Uniquely Detailed**: Real-time server state management (entire section devoted to in-memory vs. database sync)

---

## How to Use These Files

### If You're a Developer:

**Using Cursor IDE:**
→ `.cursorrules` is auto-loaded; focus on quick code patterns and tests

**Using Windsurf:**
→ `.windsurfrules` is auto-loaded; check "Common Pitfalls" for gotchas

**Using VS Code + Copilot:**
→ `copilot-instructions.md` is auto-loaded; reference "Real-Time Server State Management" section

**Asking ChatGPT or Claude:**
→ Copy `llms.txt` content into chat for context

**Asking Google Gemini:**
→ Copy `.geminirules` content into chat for optimal context

### If You're Maintaining the Project:

**Keep these in sync:**
1. Core patterns should match across all files
2. Commands should be identical (.cursorrules vs .windsurfrules)
3. File locations should be consistent (use path helpers)
4. Remove references to nonexistent APIs (e.g., export_api.py)

**Update schedule:**
- After API changes → Update `copilot-instructions.md` first (most detailed)
- After command changes → Update CLI examples across: `llms.txt`, `.cursorrules`, `.windsurfrules`
- After architecture changes → Update `.geminirules` with new components

---

## Consistency Checklist

Use this to verify all rules files are synchronized:

- [ ] HL7 command: `python3 -m medaudit.hl7server start --port 2575` (NOT `python3 -m hl7server start`)
- [ ] Web command: `python3 -m medaudit web --port 8080`
- [ ] Proxy command: `python3 -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575`
- [ ] User creation: `python3 -m medaudit user --create --username X --password Y` (web UI registration is primary)
- [ ] No mention of `/api/export/*` endpoints (not implemented)
- [ ] No mention of `config --set` command (only `config --show` and `config --create`)
- [ ] No mention of `hl7server status` command (doesn't exist)
- [ ] PII detection uses Presidio (dual-mode: structured HL7 + NLP fallback)
- [ ] MLLP framing is `\x0b...\x1c\r` (not `\x1c\n`)
- [ ] Binary decoding uses `errors='ignore'`
- [ ] Database models documented (User, Project, PcapAnalysis, ClientSession, FuzzingJob, ServerInstance)

---

## Recent Updates (February 11, 2026)

**Fixed**:
✅ Removed export API references from `.github/copilot-instructions.md` (no export_api.py implementation)
✅ Fixed HL7 server commands in README.md (removed non-existent `--set` and `status`)
✅ Added user management to command reference
✅ Fixed `.windsurfrules`: changed `python3 -m hl7server` → `python3 -m medaudit.hl7server`
✅ Added Agent Responsibilities section to copilot-instructions.md
✅ Created `.geminirules` with comprehensive Gemini-ready context

**Verified**:
✅ All commands are accurate and tested
✅ All file locations are correct
✅ No stray references to removed APIs remain
✅ Cross-file consistency improved

---

## Future Improvements

- [ ] Add `.clauderules` for Anthropic Claude (similar to Gemini rules)
- [ ] Add `.gptrules` for OpenAI GPT-4 (commercial use case)
- [ ] Create AI_ASSISTANT_EXAMPLES.md with sample Q&A for each platform
- [ ] Add version field to each rules file for tracking updates
- [ ] Create automated consistency checker (linter for rules files)
- [ ] Document which files are suitable for which tasks (decision tree)

---

## Links & References

| File | Path | Size | Format |
|------|------|------|--------|
| Cursor Rules | `.github/.cursorrules` | 200 lines | Markdown |
| Windsurf Rules | `.github/.windsurfrules` | 150 lines | Plaintext |
| Gemini Rules | `.github/.geminirules` | 450 lines | Markdown |
| Generic LLMs | `.github/llms.txt` | 120 lines | Plaintext |
| Copilot Instructions | `.github/copilot-instructions.md` | 680 lines | Markdown |
| README.md | `README.md` | 593 lines | Markdown |

---

## Questions?

When working with Medaudit:
1. **Is it a Cursor/Windsurf IDE question?** → Use tool-specific rules files (auto-loaded)
2. **Is it a Copilot question in VS Code?** → Reference `copilot-instructions.md`
3. **Is it a chat-based question (Claude/GPT)?** → Use `llms.txt`
4. **Is it a Gemini question?** → Use `.geminirules`
5. **Still unsure?** → Post in project README's contributing section

Last updated: **February 11, 2026**
