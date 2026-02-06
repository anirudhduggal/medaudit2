# Medaudit 2.0 Documentation

Complete documentation for the medical device security analyzer.

---

## 📚 Quick Navigation

### Getting Started
- **[AI Quick Start Guide](AI_QUICK_START.md)** - Get AI analysis running in 5 minutes
  - OpenAI, Anthropic, or local models (Ollama/LM Studio)
  - Step-by-step configuration
  - Example prompts to try

### Feature Documentation
- **[AI Analysis Guide](AI_ANALYSIS_GUIDE.md)** - Complete AI feature documentation
  - Supported providers (OpenAI, Anthropic, Custom)
  - Configuration options
  - API reference
  - Security & privacy considerations
  - Local model setup
  - Troubleshooting

- **[AI Context Guide](AI_CONTEXT_GUIDE.md)** - Understanding what data the AI sees
  - Complete breakdown of data exposure
  - PCAP traffic details
  - Fuzzing results
  - Server logs and client sessions
  - Privacy recommendations
  - Token usage estimates

### Security & Administration
- **[Admin Credentials](ADMIN_CREDENTIALS.md)** - Default admin account security
  - Default credentials: `admin` / `admin123`
  - Password management
  - Security best practices
  - Production deployment recommendations
  - Rate limiting and session management

- **[Default Admin Implementation](DEFAULT_ADMIN_IMPLEMENTATION.md)** - Technical implementation details
  - Code changes summary
  - Password hashing (PBKDF2-SHA256)
  - Security features
  - Migration notes

- **[Registration Implementation](REGISTRATION_IMPLEMENTATION.md)** - ★ NEW: User self-registration feature
  - Tabbed login/register interface
  - Registration endpoint details
  - Security features (rate limiting, validation)
  - Testing instructions
  - Complete implementation summary

### Project Maintenance
- **[Code Analysis Report](CODE_ANALYSIS_REPORT.md)** - Code quality and redundancy analysis
  - Codebase health assessment
  - Pattern analysis results
  - Architecture validation
  - No redundant code detected

---

## 🎯 Documentation by Use Case

### I want to analyze security findings with AI
1. Start here: [AI Quick Start](AI_QUICK_START.md)
2. Configure your provider
3. Upload a PCAP or run fuzzing
4. Ask the AI questions

### I want to understand what data the AI can access
- Read: [AI Context Guide](AI_CONTEXT_GUIDE.md)
- Covers: Traffic logs, PII findings, fuzzing results, server logs

### I want to set up privacy-focused AI (local models)
- Read: [AI Quick Start - Option 3](AI_QUICK_START.md#option-3-using-local-models-free--private)
- Or: [AI Analysis Guide - Local Models](AI_ANALYSIS_GUIDE.md#using-local-models-privacy-first)

### I'm deploying to production
- Read: [Admin Credentials - Production Setup](ADMIN_CREDENTIALS.md#production-deployment)
- Change default admin password
- Review security settings
- Enable user registration or keep admin-only access

### I want to add user accounts
- Read: [Registration Implementation](REGISTRATION_IMPLEMENTATION.md)
- Feature: Tabbed login/register interface
- Self-service user registration with email validation
- Rate-limited to prevent abuse

### I need to check code quality
- Read: [Code Analysis Report](CODE_ANALYSIS_REPORT.md)
- No redundant code detected
- Architecture validated
- Best practices followed

### I need API documentation
- Read: [AI Analysis Guide - API Reference](AI_ANALYSIS_GUIDE.md#api-reference)
- Endpoints: config, chat, analyze, suggestions, providers

---

## 📖 Main Documentation

For complete project documentation, see:
- **[Main README](../README.md)** - Project overview, features, installation
- **Architecture documentation** in `medaudit/` subdirectories
- **Test documentation** in `tests/results/`

---
| **User registration** | [Registration Implementation](REGISTRATION_IMPLEMENTATION.md) | Feature Overview |
| **Code quality check** | [Code Analysis Report](CODE_ANALYSIS_REPORT.md) | Analysis Results |

## 🆘 Quick Links

| Need | Document | Section |
|------|----------|---------|
| **AI Setup (5 min)** | [AI Quick Start](AI_QUICK_START.md) | Get Started |
| **Local AI (private)** | [AI Quick Start](AI_QUICK_START.md) | Option 3: Ollama |
| **What data AI sees** | [AI Context Guide](AI_CONTEXT_GUIDE.md) | Data Exposure |
| **Default password** | [Admin Credentials](ADMIN_CREDENTIALS.md) | Quick Start |
| **Change admin password** | [Admin Credentials](ADMIN_CREDENTIALS.md) | Password Management |
| **API endpoints** | [AI Analysis Guide](AI_ANALYSIS_GUIDE.md) | API Reference |
| **Troubleshooting** | [AI Analysis Guide](AI_ANALYSIS_GUIDE.md) | Troubleshooting |
| **Security features** | [Admin Credentials](ADMIN_CREDENTIALS.md) | Technical Details |

---

## 🔄 Document Update History

| Document | Last Updated | Version |
|----------|--------------|---------|
| AI_ANALYSIS_GUIDE.md | Feb 2026 | 2.0 |
| AI_CONTEXT_GUIDE.md | Feb 2026 | 2.0 |
| AI_QUICK_START.md | Feb 2026 | 2.0 |
| ADMIN_CREDENTIALS.md | Feb 2026 | 2.0 |
| DEFAULT_ADMIN_IMPLEMENTATION.md | Jan 2026 | 2.0 |

---

**For issues or questions, please file an issue in the project repository.**
