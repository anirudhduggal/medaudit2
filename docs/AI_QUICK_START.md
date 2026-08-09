# Quick Start: AI Analysis Feature

## 🚀 Get Started in 5 Minutes

### Option 1: Using OpenAI (Easiest)

1. **Get API Key**
   - Sign up at https://platform.openai.com
   - Create API key at https://platform.openai.com/api-keys
   - Copy your key (starts with `sk-...`)

2. **Configure in Medaudit**
   - Start server: `python3 -m medaudit web --port 8080`
   - Open http://localhost:8080
   - Login with: `admin` and your password configured via `--password` or output from `--generate-password`
   - Create or open a project
   - Click "Analyze with AI" tab
   - Select provider: **OpenAI**
   - Paste your API key
   - Model: `gpt-4` (or `gpt-3.5-turbo` for faster/cheaper)
   - Click "Save Configuration"

3. **Start Analyzing**
   - Click "Comprehensive Analysis" button
   - Or ask: "What security risks exist in this project?"
   - Review AI recommendations

**Cost**: ~$0.03 per 1K tokens (GPT-4), ~$0.002 per 1K tokens (GPT-3.5)

---

### Option 2: Using Anthropic Claude

1. **Get API Key**
   - Sign up at https://console.anthropic.com
   - Create API key in settings
   - Copy your key

2. **Configure in Medaudit**
   - Provider: **Anthropic Claude**
   - Paste API key
   - Model: `claude-3-5-sonnet-20241022`
   - Click "Save Configuration"

3. **Start Analyzing**
   - Same as OpenAI above

**Cost**: ~$0.003-0.015 per 1K tokens depending on model

---

### Option 3: Using Local Models (FREE & Private)

#### Using Ollama (Recommended for Privacy)

1. **Install Ollama**
   ```bash
   # macOS
   brew install ollama
   
   # Or download from https://ollama.ai
   ```

2. **Pull a Model**
   ```bash
   ollama pull llama3.1:70b
   # Or: mistral, codellama, phi3, etc.
   ```

3. **Start Ollama Server**
   ```bash
   ollama serve
   # Runs on http://localhost:11434
   ```

4. **Configure in Medaudit**
   - Provider: **Custom (OpenAI-compatible)**
   - API Key: `ollama` (any value works)
   - Model: `llama3.1:70b` (or whatever you pulled)
   - Base URL: `http://localhost:11434/v1`
   - Click "Save Configuration"

5. **Start Analyzing**
   - Completely private - your data never leaves your machine
   - Unlimited queries - no API costs
   - Same interface as cloud providers

**Cost**: FREE (runs locally)

---

#### Using LM Studio

1. **Install LM Studio**
   - Download from https://lmstudio.ai
   - Install and open

2. **Load a Model**
   - Search for "Mistral 7B" or "Llama 3"
   - Download and load model
   - Click "Local Server" tab
   - Start server (port 1234 by default)

3. **Configure in Medaudit**
   - Provider: **Custom (OpenAI-compatible)**
   - API Key: `lm-studio` (any value works)
   - Model: (check LM Studio's loaded model name)
   - Base URL: `http://localhost:1234/v1`
   - Click "Save Configuration"

**Cost**: FREE (runs locally)

---

## 💡 Example Prompts to Try

### After Uploading a PCAP
```
"Summarize the security findings from my PCAP analysis"
"What vulnerabilities exist in the unencrypted HL7 traffic?"
"How critical is the PII exposure found?"
"Suggest attack vectors I should test"
"Show me all SSNs found in the traffic"
"Which HL7 message types contain the most PII?"
"Analyze the connection patterns - are there anomalies?"
```

### For Pentesting Strategy
```
"Create a comprehensive pentest plan for this medical device"
"What fuzzing test cases should I prioritize?"
"How can I test for buffer overflow vulnerabilities?"
"Generate a list of creative attack scenarios"
"Based on the server logs, what weaknesses exist?"
"What do the fuzzing error patterns reveal?"
```

### For Compliance Review
```
"Are there any HIPAA compliance violations?"
"What's the privacy risk level?"
"How should this data be encrypted?"
"What recommendations would improve security posture?"
"Which PII exposures are most critical to address?"
```

### Analyzing Logs and Traffic
```
"Review the server message logs for suspicious activity"
"What do the client session errors indicate?"
"Analyze the HL7 message segments for malformed data"
"Are there any unusual response patterns from the server?"
"What can you tell from the connection timestamps?"
```

**Note**: The AI has access to comprehensive project data including all PCAP traffic, HL7 messages, PII findings, fuzzing results, server logs, and client session history. See [AI_CONTEXT_GUIDE.md](AI_CONTEXT_GUIDE.md) for details.

---

## 🎯 Quick Analysis Buttons

Click these for instant analysis:

- **🔍 Comprehensive Analysis**: Full security audit of all project findings
- **⚠️ Find Vulnerabilities**: Focus on security weaknesses
- **⚡ Attack Vectors**: Brainstorm attack scenarios

---

## ⚙️ Configuration Options

| Setting | Description | Recommended |
|---------|-------------|-------------|
| **Temperature** | Creativity (0-2) | 0.7 (balanced) |
| **Max Tokens** | Response length | 2000 (default) |
| **Model** | AI model to use | GPT-4 or Claude 3.5 Sonnet |

**Lower temperature** (0.1-0.3): More precise, factual responses  
**Higher temperature** (0.8-1.5): More creative, varied responses

---

## 🔒 Privacy Tips

### For Maximum Privacy:
1. ✅ Use Ollama or LM Studio (local models)
2. ✅ Your data never leaves your machine
3. ✅ No API costs
4. ✅ No rate limits

### When Using Cloud Providers:
1. ⚠️ Be aware data is sent to the provider
2. ⚠️ Review provider's privacy policy
3. ⚠️ Consider using for non-sensitive projects first
4. ✅ API keys stored in memory only (not saved to database)

---

## ❓ Troubleshooting

### "AI not configured"
- Make sure you clicked "Save Configuration"
- Check that provider is selected
- Verify API key is entered

### "API error" with OpenAI/Anthropic
- Check your API key is valid
- Verify you have credits/billing set up
- Try a different model

### Connection failed with Ollama
```bash
# Check Ollama is running:
curl http://localhost:11434/v1/models

# Restart Ollama:
ollama serve
```

### "Rate limit exceeded"
- Reduce max tokens
- Wait a few minutes
- Consider using local models instead

---

## 💰 Cost Comparison

| Provider | Model | Cost per 1K tokens | Privacy | Speed |
|----------|-------|-------------------|---------|-------|
| OpenAI | GPT-4 | ~$0.03-0.06 | ⚠️ Cloud | Fast |
| OpenAI | GPT-3.5 | ~$0.002 | ⚠️ Cloud | Very Fast |
| Anthropic | Claude 3.5 Sonnet | ~$0.003-0.015 | ⚠️ Cloud | Fast |
| Ollama | Llama 3.1 70B | FREE | ✅ Local | Medium |
| LM Studio | Mistral 7B | FREE | ✅ Local | Fast |

**Recommendation**: Start with Ollama (free, private) or GPT-3.5 (cheap, fast).

---

## 📚 Next Steps

1. ✅ **Try it out**: Ask the AI about your current project
2. ✅ **Upload a PCAP**: Get traffic analysis recommendations
3. ✅ **Use suggested prompts**: Click quick prompts for common tasks
4. ✅ **Experiment**: Try different questions and analysis types
5. ✅ **Read full guide**: Check [AI_ANALYSIS_GUIDE.md](AI_ANALYSIS_GUIDE.md) for details

---

## 🆘 Need Help?

- 📖 Full documentation: [AI_ANALYSIS_GUIDE.md](AI_ANALYSIS_GUIDE.md)
- 🐛 Issues: File an issue in the project repository
- 💬 Questions: Include "AI Analysis" in the subject

---

**Happy Analyzing! 🚀**
