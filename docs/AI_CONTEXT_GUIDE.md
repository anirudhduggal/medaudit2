# AI Context & Data Exposure Guide

## 📊 What Data Does the AI Have Access To?

When you use the "Analyze with AI" feature, the AI receives **comprehensive context** from your project, including all logs, traffic captures, and findings. This enables deep, evidence-based security analysis.

### ✅ Complete Data Exposure

The AI has access to:

#### 1. **PCAP Traffic Analysis** (Last 20 analyses)
- **File metadata**: Filename, size, packet count
- **Encryption analysis**: Encrypted vs unencrypted packet counts
- **Connection details**: Source/destination IPs, ports, protocols
- **Unique hosts**: All IP addresses involved in traffic
- **HL7 messages** (up to 20 per PCAP):
  - Full message timestamps
  - Source and destination
  - Message type (ADT, ORM, ORU, etc.)
  - First 5 segments of each message
  - PII presence indicators
- **PII findings** (up to 100 per PCAP):
  - Entity type (SSN, PERSON, MEDICAL_RECORD_NUMBER, etc.)
  - Actual values found (e.g., "John Doe", "123-45-6789")
  - Confidence scores
  - Location in message
  - Timestamps

#### 2. **Fuzzing Job Results** (Last 10 jobs)
- **Job configuration**: Target host/port, TLS settings
- **Status and progress**: Completion percentage, timestamps
- **Request statistics**: Total, successful, failed requests
- **Fuzzing findings** (up to 50 per job):
  - Vulnerability types identified
  - Server responses
  - Error patterns
  - Interesting behaviors
- **Sample results** (up to 30 per job):
  - Request/response pairs
  - Crash indicators
  - Timeout occurrences
- **Configuration preview**: First 500 characters of fuzzing config

#### 3. **Server Message Logs** (Last 10 servers)
- **Server configuration**: Host, port, TLS status
- **Connection statistics**: Total connections, messages received
- **Recent messages** (last 100 per server):
  - Client addresses
  - Message content
  - Timestamps
  - Message types
- **Message summary**:
  - Unique message types received
  - Recent client connections
  - Total logged messages

#### 4. **Client Session History** (Last 10 sessions)
- **Target information**: Host, port, TLS settings
- **Session status**: Connected, disconnected, error states
- **Message history** (last 50 messages per session):
  - Direction (sent/received)
  - Full message content (up to 2000 chars)
  - Responses received
  - Errors encountered
  - Timestamps
- **Message summary**:
  - Total messages sent
  - Total responses received
  - Error count

#### 5. **Project Metadata**
- Project name and description
- Engagement period (start/end dates)
- Project status (active, completed, archived)
- Creation date
- Summary counts of all analyses, jobs, servers, sessions

---

## 🎯 How the AI Uses This Context

### Smart Analysis
The AI analyzes patterns across all data sources:
```
"Based on the PCAP showing 150 unencrypted packets containing 
SSNs in PID segments, and the fuzzing results indicating buffer 
overflow in MSH-9, I recommend..."
```

### Evidence-Based Recommendations
All suggestions reference actual findings:
```
"The server logs show ACK responses with delays of 30+ seconds 
when PID-19 contains special characters, suggesting input 
validation issues..."
```

### Cross-Reference Security Issues
Correlates findings across different data sources:
```
"Your client session to 192.168.1.50:2575 successfully sent 
malformed ADT messages, but the PCAP shows no error responses, 
indicating inadequate input validation."
```

---

## 💡 Example Questions You Can Ask

### Specific to Your Data
```
"Show me all HL7 messages that contained SSNs"
"Which fuzzing payloads caused server errors?"
"What IP addresses appear most frequently in the traffic?"
"Analyze the ACK response times from the server logs"
"What PII types were found and in which message segments?"
```

### Pattern Analysis
```
"Are there any unusual patterns in the connection sequence?"
"Do the fuzzing error rates correlate with specific message types?"
"What do the server response delays indicate?"
"Are there any anomalies in the client-server message exchanges?"
```

### Comprehensive Reviews
```
"Comprehensive security analysis of all findings"
"What are the top 3 vulnerabilities based on all data?"
"Create a prioritized remediation plan"
"What attack vectors are most viable given the observed behavior?"
```

---

## 🔒 Privacy & Security Considerations

### ⚠️ Data Sent to AI Provider

When using cloud-based AI (OpenAI, Anthropic):
- **All project data is sent** to the provider's API
- This includes:
  - ✅ PII values found (SSNs, names, addresses, etc.)
  - ✅ IP addresses and network topology
  - ✅ HL7 message content
  - ✅ Server logs and client messages
  - ✅ Fuzzing configurations and results

### ✅ Privacy-First Option: Local Models

Use **Ollama** or **LM Studio** to keep all data local:

```bash
# Install Ollama
brew install ollama

# Pull a model
ollama pull llama3.1:70b

# Start Ollama (runs locally)
ollama serve

# Configure in Medaudit:
Provider: Custom
Base URL: http://localhost:11434/v1
Model: llama3.1:70b
```

**Benefits of Local Models:**
- ✅ Your data never leaves your machine
- ✅ No API costs
- ✅ Unlimited queries
- ✅ Complete privacy
- ✅ Works offline

### 🛡️ Best Practices

#### For Sensitive Projects
1. **Use local models** (Ollama/LM Studio) - 100% privacy
2. **Review context before asking** - Know what data is included
3. **Sanitize if needed** - Consider creating test projects with anonymized data

#### For Cloud Providers
1. **Review provider's privacy policy** - Understand data handling
2. **Check data retention** - How long is your data stored?
3. **Use for non-production first** - Test with synthetic data
4. **Be aware of regulations** - HIPAA, GDPR compliance considerations

#### API Key Security
1. **Never commit API keys** to version control
2. **Rotate keys regularly** - Especially if shared
3. **Use environment variables** - For production deployments
4. **Monitor usage** - Track API costs and rate limits

---

## 📈 Context Size & Token Limits

### How Much Data is Sent?

The context size varies based on your project:

| Data Type | Limit | Typical Size |
|-----------|-------|--------------|
| PCAP Analyses | Last 20 | 5-50KB per analysis |
| HL7 Messages | 20 per PCAP | 1-5KB per message |
| PII Findings | 100 per PCAP | 10-100 bytes each |
| Fuzzing Jobs | Last 10 | 2-20KB per job |
| Server Logs | Last 100 msgs | 500 bytes - 5KB |
| Client Sessions | Last 50 msgs | 500 bytes - 5KB |

**Typical total context**: 50KB - 500KB (depending on project size)

**Token usage**: ~10,000 - 100,000 tokens (varies by model tokenizer)

### Managing Large Projects

For projects with extensive data:
1. The system automatically limits data (20 PCAPs, 10 jobs, etc.)
2. You can ask targeted questions about specific analyses
3. Use project filtering if needed (future feature)

---

## 🎓 Advanced Usage

### Asking About Specific Data

Reference specific findings:
```
"Tell me about the PII found in analysis ID abc-123"
"What were the results of fuzzing job 'Buffer Overflow Test'?"
"Analyze server messages from IP 192.168.1.100"
```

### Comparative Analysis
```
"Compare the encryption status across all PCAP files"
"How do fuzzing results differ between TLS and non-TLS servers?"
"Which sessions had the highest error rates?"
```

### Time-Based Analysis
```
"What security issues emerged over time?"
"Did the engagement period show improvement in encryption?"
"When were the most PII exposures detected?"
```

---

## ❓ FAQ

### Q: Can I control what data is shared?
**A:** Currently, all project data is included for comprehensive analysis. Future versions may allow selective context.

### Q: Is my data used to train the AI?
**A:** This depends on your provider:
- **OpenAI**: Not used for training (as of 2024)
- **Anthropic**: Not used for training
- **Local models**: Data never leaves your machine

### Q: How do I delete my data from the AI provider?
**A:** Contact your provider's support for data deletion requests. Local models don't retain data.

### Q: Can I use the AI offline?
**A:** Yes, with local models (Ollama/LM Studio).

### Q: What happens if I exceed token limits?
**A:** The AI will truncate the response or return an error. Reduce `max_tokens` or ask more focused questions.

---

## 🚀 Getting Started with Full Context

1. **Upload PCAP files** - Let the AI see your traffic
2. **Run fuzzing jobs** - Generate findings for analysis
3. **Start HL7 servers** - Collect message logs
4. **Use the client** - Create session history
5. **Ask the AI** - Get comprehensive security insights

The more data you have, the better the AI's analysis!

---

**Remember**: The AI is a powerful tool, but always validate its recommendations with your security expertise.
