# AI Analysis Feature Guide

## Overview
The "Analyze with AI" tab provides agentic AI capabilities to assist with security auditing, vulnerability analysis, and penetration testing strategy development for medical devices.

## Features

### 🤖 AI-Powered Analysis
- **Interactive Chat**: Ask questions about security findings, vulnerabilities, and attack vectors
- **Project Analysis**: Automated analysis of PCAP captures, PII findings, and fuzzing results
- **Strategic Planning**: Brainstorm pentesting strategies and attack scenarios
- **Context-Aware**: AI has access to comprehensive project data including:
  - **Complete PCAP traffic data**: All packets, connections, HL7 messages with full segments
  - **PII findings**: Entity types, values, scores, locations, and timestamps
  - **Fuzzing results**: Configurations, findings, error patterns, and interesting responses
  - **Server message logs**: All messages received from clients with timestamps
  - **Client session history**: All sent/received messages, responses, and errors
  - **Traffic patterns**: Encryption status, connection details, unique hosts

### 🔑 Supported AI Providers

#### 1. OpenAI (GPT-4, GPT-3.5)
```bash
pip install openai
```
- **Models**: `gpt-4`, `gpt-4-turbo`, `gpt-3.5-turbo`
- **API Key**: Get from https://platform.openai.com/api-keys
- **Best For**: General security analysis, code review, comprehensive reports

#### 2. Anthropic Claude
```bash
pip install anthropic
```
- **Models**: `claude-3-5-sonnet-20241022`, `claude-3-opus-20240229`, `claude-3-sonnet-20240229`
- **API Key**: Get from https://console.anthropic.com/
- **Best For**: Detailed analysis, compliance reviews, long-form reports

#### 3. Custom (OpenAI-compatible)
```bash
# No installation needed if using local models
```
- **Compatible With**: Ollama, LM Studio, LocalAI, vLLM, etc.
- **Base URL Examples**:
  - Ollama: `http://localhost:11434/v1`
  - LM Studio: `http://localhost:1234/v1`
- **Best For**: Privacy-focused deployments, offline analysis

## Quick Start

### 1. Configure AI Provider
1. Navigate to project → "Analyze with AI" tab
2. Select your AI provider from the dropdown
3. Enter your API key (stored in memory only, never persisted)
4. (Optional) Customize model, temperature, and token limits
5. Click "Save Configuration"

### 2. Start Analyzing
- **Quick Prompts**: Click suggested prompts for common analysis tasks
- **Chat**: Type questions in the chat box
- **Project Analysis**: Use quick action buttons for automated analysis:
  - 🔍 **Comprehensive Analysis**: Full security audit of all findings
  - ⚠️ **Find Vulnerabilities**: Focus on potential security issues
  - ⚡ **Attack Vectors**: Brainstorm attack scenarios

### 3. Example Prompts

#### Vulnerability Analysis
```
What vulnerabilities might exist in this HL7 implementation?
Analyze the encryption status and suggest attack vectors
What are the top 5 security risks based on these findings?
```

#### PII & Compliance
```
What PII is exposed and how critical is it?
Are there any HIPAA compliance violations?
What's the privacy risk level?
```

#### Pentesting Strategy
```
Create a pentest plan for this medical device
Suggest a testing methodology
What are creative attack scenarios to explore?
```

#### Fuzzing Recommendations
```
Suggest fuzzing test cases for this HL7 server
What message fields should I fuzz first?
How can I test for buffer overflow vulnerabilities?
```

## Configuration Options

### Provider Settings
| Field | Description | Default |
|-------|-------------|---------|
| **Provider** | AI service to use | - |
| **API Key** | Your API key (memory-only) | - |
| **Model** | Specific model name | Provider default |
| **Base URL** | Custom API endpoint (for local models) | - |
| **Temperature** | Creativity level (0=precise, 2=creative) | 0.7 |
| **Max Tokens** | Maximum response length | 2000 |

### MCP Configuration (Advanced)
Medaudit includes a built-in Model Context Protocol (MCP) server that exposes core functionalities (mock server, fuzzer, PCAP analyzer, and client messaging) to external LLMs and AI agents like Claude Desktop and Cursor.

To run the MCP server, use the CLI command:
```bash
python -m medaudit mcp
```

Example configuration for Claude Desktop (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "medaudit": {
      "command": "python",
      "args": ["-m", "medaudit", "mcp"],
      "cwd": "/path/to/medaudit2",
      "env": {
        "PYTHONPATH": "/path/to/medaudit2"
      }
    }
  }
}
```
## Security & Privacy

### ✅ Privacy Features
- **API keys stored in memory only** - Never saved to database
- **No telemetry** - Your data stays between you and your chosen provider
- **Context control** - You control what data is shared with AI
- **Local model support** - Use Ollama/LM Studio for complete privacy

### ⚠️ Security Considerations
1. **API Keys**: Treat as secrets - don't share or commit to version control
2. **Data Sensitivity**: Be aware that project data is sent to the AI provider
3. **Local Models**: For maximum security, use self-hosted models (Ollama/LM Studio)
4. **Rate Limits**: Be mindful of API rate limits and costs

## Using Local Models (Privacy-First)

### Option 1: Ollama (Recommended)
```bash
# Install Ollama from https://ollama.ai
ollama pull llama3.1:70b  # or mistral, codellama, etc.

# In Medaudit AI Config:
Provider: Custom
Base URL: http://localhost:11434/v1
Model: llama3.1:70b
API Key: ollama (any value works)
```

### Option 2: LM Studio
```bash
# Download from https://lmstudio.ai
# Load a model (e.g., Mistral 7B, Llama 3, etc.)
# Start local server in LM Studio

# In Medaudit AI Config:
Provider: Custom
Base URL: http://localhost:1234/v1
Model: <model-name-from-lm-studio>
API Key: lm-studio (any value works)
```

## API Reference

### Endpoints

#### `POST /api/ai/config`
Save AI configuration for current user.
```json
{
  "provider": "openai",
  "api_key": "sk-...",
  "model": "gpt-4",
  "temperature": 0.7,
  "max_tokens": 2000
}
```

#### `GET /api/ai/config`
Get current AI configuration status (API key not returned).

#### `POST /api/ai/chat`
Send message to AI assistant.
```json
{
  "message": "What vulnerabilities exist?",
  "history": [...],
  "context": {...}
}
```

#### `POST /api/ai/projects/{project_id}/analyze`
Run automated project analysis.
```json
{
  "type": "comprehensive|vulnerabilities|pii|attack_vectors|recommendations"
}
```

#### `GET /api/ai/suggestions`
Get suggested prompts organized by category.

#### `GET /api/ai/providers`
List supported AI providers and models.

## Troubleshooting

### "AI not configured"
- Ensure you've selected a provider and entered a valid API key
- Click "Save Configuration" after entering details

### "Failed to save configuration: OpenAI library not installed"
```bash
pip install openai
# or
pip install anthropic
```

### Connection errors with local models
- Verify Ollama/LM Studio is running
- Check the base URL is correct
- Ensure the model is loaded
- Try: `curl http://localhost:11434/v1/models` (for Ollama)

### Rate limiting
- Reduce max_tokens
- Space out requests
- Consider using local models for unlimited queries

## Cost Considerations

### OpenAI Pricing (as of 2024)
- GPT-4: ~$0.03/1K input tokens, ~$0.06/1K output tokens
- GPT-3.5-turbo: ~$0.0015/1K input tokens, ~$0.002/1K output tokens

### Anthropic Pricing
- Claude 3.5 Sonnet: ~$0.003/1K input tokens, ~$0.015/1K output tokens
- Claude 3 Opus: ~$0.015/1K input tokens, ~$0.075/1K output tokens

### Free Alternatives
- **Ollama**: Completely free, run locally
- **LM Studio**: Completely free, run locally
- **OpenAI Free Tier**: $5 credit for new accounts

## Best Practices

### 1. Start with Context
Provide relevant context in your questions:
```
"Based on the PCAP analysis showing unencrypted HL7 traffic with 
exposed SSNs, what are the top security risks?"
```

### 2. Iterate and Refine
Ask follow-up questions to drill deeper:
```
User: "What vulnerabilities exist?"
AI: [Lists vulnerabilities]
User: "How would you exploit the buffer overflow you mentioned?"
```

### 3. Use Project Analysis First
Click "Comprehensive Analysis" to get AI's overview before asking specific questions.

### 4. Leverage Quick Prompts
Use suggested prompts as starting points and customize them.

### 5. Review AI Suggestions
AI analysis is a tool to assist your expertise - always validate findings independently.

## Examples

### Full Workflow Example
1. Upload PCAP file in Traffic tab
2. Switch to "Analyze with AI" tab
3. Click "Comprehensive Analysis"
4. Review AI's security assessment
5. Ask: "What should I prioritize fixing first?"
6. Ask: "Generate a fuzzing strategy for the identified vulnerabilities"
7. Switch to Fuzzer tab and implement recommendations

### Collaborative Analysis
```
You: "Summarize the security findings from my PCAP analysis"
AI: [Provides summary]
You: "Focus on the unencrypted traffic - what attack vectors exist?"
AI: [Details man-in-the-middle, sniffing, replay attacks]
You: "How can I test for replay attack vulnerabilities?"
AI: [Provides specific testing methodology]
```

## Future Enhancements

- [x] MCP (Model Context Protocol) integration
- [ ] Direct integration with fuzzer results
- [ ] Export AI recommendations to PDF reports
- [ ] Multi-turn conversation memory
- [ ] Code generation for exploit POCs
- [ ] Integration with vulnerability databases (CVE, NVD)

## Support

For issues or feature requests, please file an issue in the project repository.

---

**Note**: AI analysis is meant to augment human expertise, not replace it. Always validate AI-generated recommendations and adapt them to your specific security context.
