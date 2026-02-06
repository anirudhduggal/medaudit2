"""
AI Analysis API for Medaudit Web Application.
Provides agentic capabilities for security auditing and pentesting assistance.
"""

import os
import json
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db, Project, User
from .auth import require_auth

router = APIRouter(prefix="/api/ai", tags=["ai"])


class AIConfig(BaseModel):
    """AI configuration schema."""
    provider: str  # "openai", "anthropic", "custom"
    api_key: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None
    mcp_config: Optional[Dict[str, Any]] = None
    temperature: float = 0.7
    max_tokens: int = 2000


class ChatMessage(BaseModel):
    """Chat message schema."""
    role: str  # "user", "assistant", "system"
    content: str


class ChatRequest(BaseModel):
    """Chat request schema."""
    message: str
    context: Optional[Dict[str, Any]] = None
    history: Optional[List[ChatMessage]] = []


# In-memory storage for user AI configs (per session)
# In production, consider storing encrypted in database
_user_configs: Dict[str, AIConfig] = {}


@router.post("/config")
async def save_ai_config(
    config: AIConfig,
    user: User = Depends(require_auth)
):
    """Save AI configuration for the current user."""
    _user_configs[user.id] = config
    return {"success": True, "message": "AI configuration saved"}


@router.get("/config")
async def get_ai_config(user: User = Depends(require_auth)):
    """Get AI configuration for the current user."""
    config = _user_configs.get(user.id)
    if not config:
        return {"configured": False}
    
    # Don't send the API key back to the client
    return {
        "configured": True,
        "provider": config.provider,
        "model": config.model,
        "base_url": config.base_url,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "has_api_key": bool(config.api_key),
        "has_mcp_config": bool(config.mcp_config)
    }


@router.post("/chat")
async def chat(
    request: ChatRequest,
    user: User = Depends(require_auth)
):
    """
    Send a message to the AI assistant for analysis.
    
    The AI can help with:
    - Security analysis of HL7 traffic
    - Pentesting strategy recommendations
    - Vulnerability assessment
    - Attack vector brainstorming
    - PII exposure analysis
    """
    config = _user_configs.get(user.id)
    if not config:
        raise HTTPException(
            status_code=400,
            detail="AI not configured. Please add your API key first."
        )
    
    try:
        # Build system prompt with context
        system_prompt = build_system_prompt(request.context)
        
        # Call the appropriate AI provider
        if config.provider == "openai":
            response = await call_openai(config, system_prompt, request.message, request.history)
        elif config.provider == "anthropic":
            response = await call_anthropic(config, system_prompt, request.message, request.history)
        elif config.provider == "custom":
            response = await call_custom(config, system_prompt, request.message, request.history)
        else:
            raise HTTPException(status_code=400, detail="Unsupported AI provider")
        
        return {
            "success": True,
            "response": response,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/projects/{project_id}/analyze")
async def analyze_project(
    project_id: str,
    request: Dict[str, Any],
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Analyze a project using AI.
    
    Provides context-aware analysis including:
    - PCAP analysis results
    - PII findings
    - Fuzzing results
    - Security recommendations
    """
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    config = _user_configs.get(user.id)
    if not config:
        raise HTTPException(
            status_code=400,
            detail="AI not configured. Please add your API key first."
        )
    
    # Gather project context
    context = gather_project_context(project, db)
    
    # Build analysis prompt
    analysis_type = request.get("type", "comprehensive")
    prompt = build_analysis_prompt(analysis_type, context)
    
    try:
        if config.provider == "openai":
            response = await call_openai(config, build_system_prompt(context), prompt, [])
        elif config.provider == "anthropic":
            response = await call_anthropic(config, build_system_prompt(context), prompt, [])
        elif config.provider == "custom":
            response = await call_custom(config, build_system_prompt(context), prompt, [])
        else:
            raise HTTPException(status_code=400, detail="Unsupported AI provider")
        
        return {
            "success": True,
            "analysis": response,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def build_system_prompt(context: Optional[Dict[str, Any]] = None) -> str:
    """Build system prompt with comprehensive context including all logs and traffic data."""
    base_prompt = """You are a medical device security expert specializing in HL7 protocol analysis and penetration testing. 
You have deep knowledge of:
- HL7 v2.x and FHIR protocols
- MLLP (Minimum Lower Layer Protocol)
- Healthcare data security and HIPAA compliance
- Medical device vulnerabilities
- PII detection and data privacy
- Network security and traffic analysis
- Fuzzing and vulnerability testing

Your role is to:
1. Analyze security findings from PCAP traffic captures, including packet details, connections, and message content
2. Review HL7 message logs, including segments, fields, and PII exposure
3. Identify potential vulnerabilities in HL7 implementations based on traffic patterns and server responses
4. Analyze fuzzing results, findings, and error patterns
5. Review client-server interactions and message exchanges
6. Suggest attack vectors and pentesting strategies based on observed behavior
7. Provide recommendations for security improvements
8. Help identify PII exposure, data leakage, and compliance issues
9. Brainstorm creative testing approaches tailored to the specific environment

You have access to:
- Complete PCAP analysis results with traffic details, connections, and encryption status
- All HL7 messages captured with full segment data
- PII findings with entity types, values, scores, and locations
- Fuzzing job configurations, results, and findings
- Server message logs with client interactions
- Client session histories with sent/received messages and responses

Always provide actionable, specific advice tailored to the actual data observed in this project. Reference specific findings, messages, connections, or patterns when making recommendations."""
    
    if context:
        # Create a more structured context summary
        context_summary = f"""

=== PROJECT CONTEXT ===
Project: {context.get('project_name', 'Unknown')}
Description: {context.get('project_description', 'N/A')}
Status: {context.get('status', 'unknown')}
Engagement Period: {context.get('engagement_period', {}).get('start', 'N/A')} to {context.get('engagement_period', {}).get('end', 'N/A')}

=== SUMMARY ===
- PCAP Analyses: {context.get('summary', {}).get('total_pcap_analyses', 0)}
- Fuzzing Jobs: {context.get('summary', {}).get('total_fuzzing_jobs', 0)}
- Servers: {context.get('summary', {}).get('total_servers', 0)}
- Client Sessions: {context.get('summary', {}).get('total_client_sessions', 0)}

=== DETAILED DATA ===
The following data includes all traffic captures, logs, messages, and findings from this project.
Use this data to provide specific, evidence-based security analysis.

"""
        base_prompt += context_summary + json.dumps(context, indent=2)
    
    return base_prompt


def build_analysis_prompt(analysis_type: str, context: Dict[str, Any]) -> str:
    """Build specific analysis prompts."""
    prompts = {
        "comprehensive": "Provide a comprehensive security analysis of this project, including all findings, vulnerabilities, and recommendations.",
        "pii": "Focus on PII (Personally Identifiable Information) exposure. Analyze what sensitive data was found and assess the privacy risks.",
        "vulnerabilities": "Identify potential vulnerabilities based on the traffic patterns, message formats, and server responses observed.",
        "attack_vectors": "Suggest creative attack vectors and pentesting strategies for this medical device configuration.",
        "recommendations": "Provide prioritized security recommendations for hardening this system."
    }
    
    return prompts.get(analysis_type, prompts["comprehensive"])


def gather_project_context(project: Project, db: Session) -> Dict[str, Any]:
    """Gather comprehensive project context for AI analysis including all logs and traffic data."""
    context = {
        "project_name": project.name,
        "project_description": project.description,
        "engagement_period": {
            "start": project.engagement_start.isoformat() if project.engagement_start else None,
            "end": project.engagement_end.isoformat() if project.engagement_end else None
        },
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "status": project.status,
        "pcap_analyses": [],
        "fuzzing_jobs": [],
        "servers": [],
        "client_sessions": [],
        "summary": {
            "total_pcap_analyses": len(project.pcap_analyses),
            "total_fuzzing_jobs": len(project.fuzzing_jobs),
            "total_servers": len(project.server_instances),
            "total_client_sessions": len(project.client_sessions)
        }
    }
    
    # Add detailed PCAP analysis results with full traffic data
    for analysis in project.pcap_analyses[:20]:  # Last 20 analyses
        pcap_data = {
            "id": analysis.id,
            "filename": analysis.filename,
            "file_size": analysis.file_size,
            "total_packets": analysis.total_packets,
            "hl7_messages": analysis.hl7_message_count,
            "pii_count": analysis.pii_count,
            "encryption_status": analysis.encryption_status,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        }
        
        # Include detailed results if available
        if analysis.results:
            results = analysis.results
            pcap_data["traffic_summary"] = {
                "encrypted_packets": results.get("encrypted_packets", 0),
                "unencrypted_packets": results.get("unencrypted_packets", 0),
                "total_connections": len(results.get("connections", [])),
                "unique_hosts": len(set([
                    conn.get("src") for conn in results.get("connections", [])
                ] + [
                    conn.get("dst") for conn in results.get("connections", [])
                ])) if results.get("connections") else 0
            }
            
            # Include connection details (limited)
            if results.get("connections"):
                pcap_data["connections"] = results["connections"][:50]  # First 50 connections
            
            # Include HL7 messages (limited)
            if results.get("hl7_messages"):
                pcap_data["hl7_messages"] = [
                    {
                        "timestamp": msg.get("timestamp"),
                        "src": msg.get("src"),
                        "dst": msg.get("dst"),
                        "message_type": msg.get("message_type"),
                        "segments": msg.get("segments", [])[:5],  # First 5 segments
                        "has_pii": len(msg.get("pii", [])) > 0,
                        "pii_count": len(msg.get("pii", []))
                    }
                    for msg in results["hl7_messages"][:20]  # First 20 messages
                ]
            
            # Include PII findings with full details
            if results.get("pii_instances"):
                pcap_data["pii_findings"] = [
                    {
                        "type": pii.get("entity_type"),
                        "value": pii.get("value"),
                        "score": pii.get("score"),
                        "location": pii.get("location"),
                        "timestamp": pii.get("timestamp")
                    }
                    for pii in results["pii_instances"][:100]  # First 100 PII instances
                ]
        
        context["pcap_analyses"].append(pcap_data)
    
    # Add comprehensive fuzzing job results with findings
    for job in project.fuzzing_jobs[:10]:  # Last 10 jobs
        job_data = {
            "id": job.id,
            "name": job.name,
            "status": job.status,
            "target": f"{job.target_host}:{job.target_port}",
            "use_tls": job.use_tls,
            "progress": job.progress,
            "total_requests": job.total_requests,
            "successful_requests": job.successful_requests,
            "error_requests": job.error_requests,
            "interesting_findings": job.interesting_findings,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None
        }
        
        # Include fuzzing configuration
        if job.config_content:
            job_data["config_preview"] = job.config_content[:500]  # First 500 chars
        
        # Include findings with details
        if job.findings:
            job_data["findings"] = job.findings[:50]  # First 50 findings
        
        # Include sample results
        if job.results:
            job_data["sample_results"] = job.results[:30]  # First 30 results
        
        context["fuzzing_jobs"].append(job_data)
    
    # Add server instances with message logs
    for server in project.server_instances[:10]:
        server_data = {
            "id": server.id,
            "name": server.name,
            "host": server.host,
            "port": server.port,
            "use_tls": server.use_tls,
            "status": server.status,
            "total_connections": server.total_connections,
            "total_messages": server.total_messages,
            "created_at": server.created_at.isoformat() if server.created_at else None
        }
        
        # Include message logs if available
        if server.message_log:
            server_data["recent_messages"] = server.message_log[-100:]  # Last 100 messages
            server_data["message_summary"] = {
                "total_logged": len(server.message_log),
                "message_types": list(set([
                    msg.get("message_type") for msg in server.message_log
                    if msg.get("message_type")
                ])),
                "recent_connections": list(set([
                    msg.get("client_address") for msg in server.message_log[-50:]
                    if msg.get("client_address")
                ]))
            }
        
        context["servers"].append(server_data)
    
    # Add client session history with messages
    for session in project.client_sessions[:10]:  # Last 10 sessions
        session_data = {
            "id": session.id,
            "target": f"{session.target_host}:{session.target_port}",
            "use_tls": session.use_tls,
            "status": session.status,
            "message_count": len(session.message_history) if session.message_history else 0,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None
        }
        
        # Include message history (last 50 messages)
        if session.message_history:
            session_data["message_history"] = session.message_history[-50:]
            session_data["message_summary"] = {
                "total_sent": len([m for m in session.message_history if m.get("direction") == "sent"]),
                "total_received": len([m for m in session.message_history if m.get("direction") == "received"]),
                "errors": len([m for m in session.message_history if m.get("error")])
            }
        
        context["client_sessions"].append(session_data)
    
    return context


async def call_openai(config: AIConfig, system_prompt: str, message: str, history: List[ChatMessage]) -> str:
    """Call OpenAI API."""
    try:
        import openai
        
        client = openai.OpenAI(
            api_key=config.api_key,
            base_url=config.base_url if config.base_url else None
        )
        
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add history
        for msg in history[-10:]:  # Last 10 messages
            messages.append({"role": msg.role, "content": msg.content})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        response = client.chat.completions.create(
            model=config.model or "gpt-4",
            messages=messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens
        )
        
        return response.choices[0].message.content
        
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="OpenAI library not installed. Run: pip install openai"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI API error: {str(e)}")


async def call_anthropic(config: AIConfig, system_prompt: str, message: str, history: List[ChatMessage]) -> str:
    """Call Anthropic Claude API."""
    try:
        import anthropic
        
        client = anthropic.Anthropic(api_key=config.api_key)
        
        messages = []
        
        # Add history
        for msg in history[-10:]:
            if msg.role != "system":
                messages.append({"role": msg.role, "content": msg.content})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        response = client.messages.create(
            model=config.model or "claude-3-5-sonnet-20241022",
            system=system_prompt,
            messages=messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens
        )
        
        return response.content[0].text
        
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Anthropic library not installed. Run: pip install anthropic"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Anthropic API error: {str(e)}")


async def call_custom(config: AIConfig, system_prompt: str, message: str, history: List[ChatMessage]) -> str:
    """Call custom OpenAI-compatible API."""
    if not config.base_url:
        raise HTTPException(status_code=400, detail="Custom provider requires base_url")
    
    # Use OpenAI client with custom base URL
    return await call_openai(config, system_prompt, message, history)


@router.get("/providers")
async def get_providers(user: User = Depends(require_auth)):
    """Get list of supported AI providers."""
    return {
        "providers": [
            {
                "id": "openai",
                "name": "OpenAI",
                "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
                "requires_api_key": True,
                "supports_custom_url": True
            },
            {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "models": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-sonnet-20240229"],
                "requires_api_key": True,
                "supports_custom_url": False
            },
            {
                "id": "custom",
                "name": "Custom (OpenAI-compatible)",
                "models": [],
                "requires_api_key": True,
                "supports_custom_url": True,
                "description": "Any OpenAI-compatible API (Ollama, LM Studio, etc.)"
            }
        ]
    }


@router.get("/suggestions")
async def get_suggestions(user: User = Depends(require_auth)):
    """Get AI prompt suggestions for pentesting."""
    return {
        "categories": [
            {
                "name": "Vulnerability Analysis",
                "prompts": [
                    "What vulnerabilities might exist in this HL7 implementation?",
                    "Analyze the encryption status and suggest attack vectors",
                    "What are the top 5 security risks based on these findings?",
                    "How could an attacker exploit the PII exposure found?"
                ]
            },
            {
                "name": "Fuzzing Strategy",
                "prompts": [
                    "Suggest fuzzing test cases for this HL7 server",
                    "What message fields should I fuzz first?",
                    "Generate malformed HL7 messages for testing",
                    "How can I test for buffer overflow vulnerabilities?"
                ]
            },
            {
                "name": "Traffic Analysis",
                "prompts": [
                    "Analyze these PCAP results and identify anomalies",
                    "What does the message flow pattern reveal?",
                    "Are there any suspicious connection patterns?",
                    "Summarize the security posture of this traffic"
                ]
            },
            {
                "name": "PII & Compliance",
                "prompts": [
                    "What PII is exposed and how critical is it?",
                    "Are there any HIPAA compliance violations?",
                    "How should this data be encrypted?",
                    "What's the privacy risk level?"
                ]
            },
            {
                "name": "Pentest Planning",
                "prompts": [
                    "Create a pentest plan for this medical device",
                    "What tools should I use for testing?",
                    "Suggest a testing methodology",
                    "What are creative attack scenarios to explore?"
                ]
            }
        ]
    }
