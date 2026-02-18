"""
AI Assistant API for Medaudit Web Application.

Provides endpoints for AI-powered pentest assistance:
- API key configuration and model selection
- Chat with full project context
- Auto-analysis of events
- Executing AI-suggested actions
- Token usage tracking
"""

import logging
import threading
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db, User, Project
from .auth import require_auth
from .ai.providers import get_provider, AIProvider, usage_tracker, AnthropicProvider
from .ai.context import context_engine
from .ai.prompts import SYSTEM_PROMPT, AUTO_ANALYZE_PROMPT, CONTEXT_SUMMARY_PROMPT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai"])


# =============================================================================
# Global AI configuration (multi-provider, stored in memory per session)
# =============================================================================

# Each configured provider: { "provider": AIProvider, "models": [...], "default_model": "..." }
_providers: Dict[str, Dict[str, Any]] = {}  # provider_type -> config

# Active provider selection (which provider+model is currently being used)
_active_provider_type: Optional[str] = None
_active_model: Optional[str] = None

# Global settings
_global_settings: Dict[str, Any] = {
    "auto_analyze": True,
}

_chat_history: Dict[str, List[Dict[str, str]]] = {}  # project_id -> message history
_auto_insights: Dict[str, List[Dict[str, Any]]] = {}  # project_id -> insights
_auto_analyze_thread: Optional[threading.Thread] = None
_auto_analyze_running = False

_config_lock = threading.Lock()


def _get_active_provider() -> Optional[AIProvider]:
    """Get the currently active provider instance."""
    with _config_lock:
        if _active_provider_type and _active_provider_type in _providers:
            return _providers[_active_provider_type]["provider"]
    return None


def _get_active_model() -> Optional[str]:
    """Get the currently active model."""
    with _config_lock:
        return _active_model


def _is_configured() -> bool:
    """Check if any provider is configured."""
    with _config_lock:
        return len(_providers) > 0


def _load_project_credentials(project_id: str, db: Session) -> bool:
    """
    Load AI credentials for a project from the database.
    Returns True if at least one active credential was loaded.
    """
    global _active_provider_type, _active_model
    
    from .database import AICredential
    credentials = db.query(AICredential).filter(
        AICredential.project_id == project_id
    ).all()
    
    if not credentials:
        return False
    
    loaded_count = 0
    with _config_lock:
        for cred in credentials:
            try:
                provider = get_provider(
                    provider_type=cred.provider,
                    api_key=cred.api_key,
                    base_url=cred.base_url,
                )
                
                # Validate the loaded credential
                is_valid, _ = provider.validate_key()
                if is_valid:
                    models = provider.list_models()
                    _providers[cred.provider] = {
                        "provider": provider,
                        "models": models,
                        "default_model": cred.default_model or (models[0]["id"] if models else None),
                    }
                    loaded_count += 1
                    
                    # Set as active if marked so
                    if cred.is_active:
                        _active_provider_type = cred.provider
                        _active_model = cred.default_model or (models[0]["id"] if models else None)
            except (ValueError, RuntimeError) as e:
                logger.warning(f"Failed to load credential for {cred.provider}: {e}")
                continue
    
    return loaded_count > 0


# =============================================================================
# Request/Response Schemas
# =============================================================================

class ConfigureProviderRequest(BaseModel):
    provider: str  # "anthropic", "openai", "gemini", "ollama"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    default_model: Optional[str] = None


class SetActiveRequest(BaseModel):
    provider: str
    model: str


class ChatRequest(BaseModel):
    message: str
    project_id: str
    include_context: bool = True


class ExecuteActionRequest(BaseModel):
    action_type: str
    action_data: Dict[str, Any]
    project_id: str


# =============================================================================
# Configuration Endpoints
# =============================================================================

@router.post("/providers/configure")
async def configure_provider(
    config: ConfigureProviderRequest,
    user: User = Depends(require_auth),
):
    """
    Configure (add/update) an AI provider globally.
    Validates the key and fetches available models.
    """
    global _active_provider_type, _active_model
    
    try:
        provider = get_provider(
            provider_type=config.provider,
            api_key=config.api_key,
            base_url=config.base_url,
        )
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Validate key
    is_valid, error = provider.validate_key()
    if not is_valid:
        raise HTTPException(status_code=401, detail=f"API key validation failed: {error}")
    
    # Fetch available models
    models = provider.list_models()
    
    # Pick default model
    default_model = config.default_model
    if not default_model and models:
        default_model = models[0]["id"]
    
    with _config_lock:
        _providers[config.provider] = {
            "provider": provider,
            "models": models,
            "default_model": default_model,
        }
        
        # If no active provider yet, set this as active
        if _active_provider_type is None:
            _active_provider_type = config.provider
            _active_model = default_model
    
    # Start auto-analyze if first provider
    _start_auto_analyze()
    
    return {
        "success": True,
        "provider": config.provider,
        "models": models,
        "default_model": default_model,
    }


@router.post("/providers/validate")
async def validate_provider_key(
    config: ConfigureProviderRequest,
    user: User = Depends(require_auth),
):
    """Validate an API key and return available models without saving."""
    try:
        provider = get_provider(
            provider_type=config.provider,
            api_key=config.api_key,
            base_url=config.base_url,
        )
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    is_valid, error = provider.validate_key()
    if not is_valid:
        return {"valid": False, "error": error, "models": []}
    
    models = provider.list_models()
    return {"valid": True, "models": models, "provider": config.provider}


@router.post("/providers/remove")
async def remove_provider(
    request: dict,
    user: User = Depends(require_auth),
):
    """Remove a configured provider and wipe its API key from memory."""
    global _active_provider_type, _active_model
    
    provider_type = request.get("provider")
    if not provider_type:
        raise HTTPException(status_code=400, detail="provider is required")
    
    with _config_lock:
        if provider_type in _providers:
            # Wipe the key
            p = _providers[provider_type]["provider"]
            if hasattr(p, 'api_key'):
                p.api_key = None
            if hasattr(p, '_client'):
                p._client = None
            del _providers[provider_type]
        
        # If we removed the active provider, switch to another or clear
        if _active_provider_type == provider_type:
            if _providers:
                _active_provider_type = next(iter(_providers))
                _active_model = _providers[_active_provider_type]["default_model"]
            else:
                _active_provider_type = None
                _active_model = None
    
    return {"success": True}


@router.get("/providers")
async def list_configured_providers(user: User = Depends(require_auth)):
    """List all configured providers with their models (without exposing keys)."""
    from .ai.providers import PROVIDER_INFO
    
    with _config_lock:
        configured = {}
        for ptype, pconfig in _providers.items():
            configured[ptype] = {
                "configured": True,
                "models": pconfig["models"],
                "default_model": pconfig["default_model"],
                "info": PROVIDER_INFO.get(ptype, {}),
            }
        
        return {
            "providers": configured,
            "active_provider": _active_provider_type,
            "active_model": _active_model,
            "available_providers": {
                k: v for k, v in PROVIDER_INFO.items()
            },
        }


@router.get("/config")
async def get_ai_config(user: User = Depends(require_auth)):
    """Get current AI configuration status."""
    with _config_lock:
        return {
            "configured": len(_providers) > 0,
            "provider": _active_provider_type,
            "model": _active_model,
            "auto_analyze": _global_settings["auto_analyze"],
            "provider_count": len(_providers),
        }


@router.post("/set-active")
async def set_active_provider(
    request: SetActiveRequest,
    user: User = Depends(require_auth),
):
    """Set the active provider and model for chat."""
    global _active_provider_type, _active_model
    
    with _config_lock:
        if request.provider not in _providers:
            raise HTTPException(status_code=400, detail=f"Provider '{request.provider}' not configured")
        
        _active_provider_type = request.provider
        _active_model = request.model
    
    return {"success": True, "provider": request.provider, "model": request.model}


@router.post("/disconnect")
async def disconnect_all(user: User = Depends(require_auth)):
    """Disconnect all providers and wipe all keys from memory."""
    global _active_provider_type, _active_model, _auto_analyze_running
    
    with _config_lock:
        for ptype, pconfig in _providers.items():
            p = pconfig["provider"]
            if hasattr(p, 'api_key'):
                p.api_key = None
            if hasattr(p, '_client'):
                p._client = None
        _providers.clear()
        _active_provider_type = None
        _active_model = None
    
    _auto_analyze_running = False
    _chat_history.clear()
    _auto_insights.clear()
    usage_tracker.reset()
    
    return {"success": True, "message": "All AI providers disconnected. Keys wiped from memory."}


@router.post("/toggle-auto-analyze")
async def toggle_auto_analyze(
    request: dict,
    user: User = Depends(require_auth),
):
    """Toggle auto-analyze on/off."""
    enabled = request.get("enabled", True)
    with _config_lock:
        _global_settings["auto_analyze"] = enabled
    if enabled:
        _start_auto_analyze()
    return {"success": True, "auto_analyze": enabled}


# =============================================================================
# Project-Level AI Credentials (for persistence across sessions)
# =============================================================================

@router.post("/projects/{project_id}/ai-credentials")
async def save_project_credential(
    project_id: str,
    config: ConfigureProviderRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Save an AI provider credential to a project in the database.
    Credentials are stored per-project and persist across server restarts.
    """
    # Verify user owns this project
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Validate the credential
    try:
        provider = get_provider(
            provider_type=config.provider,
            api_key=config.api_key,
            base_url=config.base_url,
        )
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    is_valid, error = provider.validate_key()
    if not is_valid:
        raise HTTPException(status_code=401, detail=f"API key validation failed: {error}")
    
    # Get available models
    models = provider.list_models()
    default_model = config.default_model or (models[0]["id"] if models else None)
    
    # Check if credential already exists
    from .database import AICredential
    existing = db.query(AICredential).filter(
        AICredential.project_id == project_id,
        AICredential.provider == config.provider
    ).first()
    
    if existing:
        # Update existing credential
        existing.api_key = config.api_key
        existing.base_url = config.base_url or None
        existing.default_model = default_model
        existing.last_validated = datetime.utcnow()
        existing.validation_error = None
        existing.is_active = True  # Set as active
    else:
        # Create new credential
        cred = AICredential(
            project_id=project_id,
            provider=config.provider,
            api_key=config.api_key,
            base_url=config.base_url or None,
            default_model=default_model,
            is_active=True,
            last_validated=datetime.utcnow(),
        )
        db.add(cred)
    
    # Deactivate other providers for this project
    db.query(AICredential).filter(
        AICredential.project_id == project_id,
        AICredential.provider != config.provider
    ).update({AICredential.is_active: False})
    
    db.commit()
    
    return {
        "success": True,
        "provider": config.provider,
        "models": models,
        "default_model": default_model,
        "saved_to_project": True
    }


@router.get("/projects/{project_id}/ai-credentials")
async def get_project_credentials(
    project_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Get AI provider credentials saved to a project (without exposing keys).
    """
    # Verify user owns this project
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    from .database import AICredential
    credentials = db.query(AICredential).filter(
        AICredential.project_id == project_id
    ).all()
    
    return {
        "project_id": project_id,
        "credentials": [cred.to_dict() for cred in credentials],
        "active_provider": next(
            (c.provider for c in credentials if c.is_active), None
        )
    }


@router.delete("/projects/{project_id}/ai-credentials/{provider}")
async def delete_project_credential(
    project_id: str,
    provider: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Delete an AI provider credential from a project.
    """
    # Verify user owns this project
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    from .database import AICredential
    cred = db.query(AICredential).filter(
        AICredential.project_id == project_id,
        AICredential.provider == provider
    ).first()
    
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    db.delete(cred)
    db.commit()
    
    return {"success": True, "message": f"Credential for {provider} deleted"}


# =============================================================================
# Chat Endpoint
# =============================================================================

@router.post("/chat")
async def chat(
    request: ChatRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Send a message to the AI with full project context.
    Optionally accepts provider/model override in the request.
    Loads project-saved credentials from database if needed.
    """
    # Try to load project credentials if none configured in memory
    if not _is_configured():
        _load_project_credentials(request.project_id, db)
    
    provider = _get_active_provider()
    model = _get_active_model()
    
    if not provider or not model:
        raise HTTPException(
            status_code=400,
            detail="No AI provider configured. Go to Settings to add one."
        )
    
    # Verify project access
    project = db.query(Project).filter(
        Project.id == request.project_id,
        Project.owner_id == user.id,
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build context
    context = ""
    if request.include_context:
        context = context_engine.build_context(request.project_id, db, include_full_logs=True)
    
    # Build system prompt with context
    full_system = SYSTEM_PROMPT
    if context:
        full_system += f"\n\n## Current Project Context\n{context}"
    
    # Get or create chat history for this project
    if request.project_id not in _chat_history:
        _chat_history[request.project_id] = []
    
    history = _chat_history[request.project_id]
    
    # Add user message
    history.append({"role": "user", "content": request.message})
    
    # Keep history manageable (last 20 messages)
    if len(history) > 20:
        history = history[-20:]
        _chat_history[request.project_id] = history
    
    # Send to AI
    response = provider.chat(
        messages=history,
        system_prompt=full_system,
        model=model,
        max_tokens=4096,
        temperature=0.3,
    )
    
    if response.error:
        raise HTTPException(status_code=500, detail=f"AI error: {response.error}")
    
    # Record usage
    usage_tracker.record(response.usage)
    
    # Add assistant response to history
    history.append({"role": "assistant", "content": response.content})
    
    return response.to_dict()


@router.post("/clear-history")
async def clear_chat_history(
    request: dict,
    user: User = Depends(require_auth),
):
    """Clear chat history for a project."""
    project_id = request.get("project_id")
    if project_id and project_id in _chat_history:
        _chat_history[project_id] = []
    return {"success": True}


# =============================================================================
# Auto-Analysis & Insights
# =============================================================================

@router.get("/insights/{project_id}")
async def get_insights(
    project_id: str,
    user: User = Depends(require_auth),
):
    """Get auto-generated insights for a project."""
    insights = _auto_insights.get(project_id, [])
    
    # Return last 10 insights
    return {
        "insights": insights[-10:],
        "total": len(insights),
    }


@router.post("/analyze-now")
async def analyze_now(
    request: dict,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Trigger an immediate analysis of the current project state.
    Useful for getting a status overview on demand.
    """
    project_id = request.get("project_id")
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id is required")

    provider = _get_active_provider()
    model = _get_active_model()
    
    if not provider or not model:
        raise HTTPException(status_code=400, detail="No AI provider configured. Go to Settings to add one.")
    
    # Build full context
    context = context_engine.build_context(project_id, db, include_full_logs=True)
    
    full_system = SYSTEM_PROMPT
    messages = [
        {
            "role": "user",
            "content": f"{CONTEXT_SUMMARY_PROMPT}\n\n{context}"
        }
    ]
    
    response = provider.chat(
        messages=messages,
        system_prompt=full_system,
        model=model,
        max_tokens=2048,
        temperature=0.2,
    )
    
    if response.error:
        raise HTTPException(status_code=500, detail=f"AI error: {response.error}")
    
    usage_tracker.record(response.usage)
    
    # Store as insight
    insight = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "manual_analysis",
        "content": response.content,
        "actions": response.actions,
        "insights": response.insights,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cost_usd": response.usage.estimated_cost_usd,
        }
    }
    
    if project_id not in _auto_insights:
        _auto_insights[project_id] = []
    _auto_insights[project_id].append(insight)
    
    return response.to_dict()


# =============================================================================
# Action Execution
# =============================================================================

@router.post("/execute-action")
async def execute_action(
    request: ExecuteActionRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Execute an AI-suggested action.
    
    Supported action types:
    - send_payload: Send an HL7 message to a target
    - start_fuzzer: Start a fuzzing job with given config
    - start_server: Start an HL7 server
    - upload_pcap: Trigger PCAP analysis (requires file)
    """
    action_type = request.action_type
    data = request.action_data
    project_id = request.project_id
    
    # Verify project access
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id,
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    try:
        if action_type == "send_payload":
            result = await _execute_send_payload(data, db)
        elif action_type == "start_fuzzer":
            result = await _execute_start_fuzzer(data, project_id, user, db)
        elif action_type == "start_server":
            result = await _execute_start_server(data, project_id, user, db)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown action type: {action_type}"
            )
        
        # Log the action as an event
        context_engine.add_event(
            module="ai",
            event_type="action_executed",
            data={
                "action_type": action_type,
                "result": "success",
                "details": str(result)[:200],
            }
        )
        
        return {"success": True, "result": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Action execution failed: {e}")
        context_engine.add_event(
            module="ai",
            event_type="action_failed",
            data={
                "action_type": action_type,
                "error": str(e),
            }
        )
        raise HTTPException(status_code=500, detail=f"Action failed: {str(e)}")


async def _execute_send_payload(data: dict, db: Session) -> dict:
    """Execute a send_payload action."""
    from .client_api import send_hl7_message, format_message
    
    target_host = data.get("target_host", "localhost")
    target_port = int(data.get("target_port", 2575))
    message = data.get("message", "")
    use_tls = data.get("use_tls", False)
    
    if not message:
        raise HTTPException(status_code=400, detail="Message is required")
    
    formatted = format_message(message)
    result = send_hl7_message(target_host, target_port, formatted, use_tls)
    
    # Log as client event
    context_engine.add_event(
        module="client",
        event_type="payload_sent",
        data={
            "target": f"{target_host}:{target_port}",
            "response_status": "success" if result.get("success") else "error",
            "message_preview": message[:100],
        }
    )
    
    return result


async def _execute_start_fuzzer(data: dict, project_id: str, user, db: Session) -> dict:
    """Execute a start_fuzzer action."""
    from .fuzzer_api import create_fuzzing_job
    from medaudit.fuzzer import parse_fuzzing_config
    from medaudit.fuzzer.engine import validate_config
    
    config_content = data.get("config", "")
    name = data.get("label", "AI-suggested fuzzing")
    
    if not config_content:
        raise HTTPException(status_code=400, detail="Fuzzing config is required")
    
    # Parse and validate
    config = parse_fuzzing_config(config_content, "yaml")
    is_valid, errors = validate_config(config)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid config: {'; '.join(errors)}")
    
    # Create the job
    from .database import FuzzingJob, get_db_manager
    import threading
    from medaudit.fuzzer import run_fuzzing_job
    
    job = FuzzingJob(
        project_id=project_id,
        name=name,
        target_host=config.get("target_host", "localhost"),
        target_port=config.get("target_port", 2575),
        use_tls=config.get("use_tls", False),
        config_format="yaml",
        config_content=config_content,
        status="pending",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    db_manager = get_db_manager()
    thread = threading.Thread(
        target=run_fuzzing_job,
        args=(job.id, config, db_manager.SessionLocal),
        daemon=True,
    )
    thread.start()
    
    context_engine.add_event(
        module="fuzzer",
        event_type="started",
        data={"name": name, "target": f"{config.get('target_host')}:{config.get('target_port')}"}
    )
    
    return {"job_id": job.id, "status": "started"}


async def _execute_start_server(data: dict, project_id: str, user, db: Session) -> dict:
    """Execute a start_server action."""
    from .database import ServerInstance, get_db_manager
    from .server_api import run_server
    import threading
    
    port = int(data.get("port", 2575))
    name = data.get("name", f"AI Server (port {port})")
    
    server = ServerInstance(
        project_id=project_id,
        name=name,
        host="0.0.0.0",
        port=port,
        use_tls=False,
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    
    db_manager = get_db_manager()
    config = {"host": "0.0.0.0", "port": port, "use_tls": False}
    
    thread = threading.Thread(
        target=run_server,
        args=(server.id, config, db_manager.SessionLocal),
        daemon=True,
    )
    thread.start()
    
    time.sleep(0.5)
    
    context_engine.add_event(
        module="server",
        event_type="server",
        data={"action": "started", "port": port, "name": name}
    )
    
    return {"server_id": server.id, "port": port, "status": "started"}


# =============================================================================
# Usage Tracking
# =============================================================================

@router.get("/usage")
async def get_usage(user: User = Depends(require_auth)):
    """Get token usage statistics for the current session."""
    return usage_tracker.get_session_totals()


@router.post("/usage/reset")
async def reset_usage(user: User = Depends(require_auth)):
    """Reset usage tracking."""
    usage_tracker.reset()
    return {"success": True}


# =============================================================================
# Auto-Analyze Background Worker
# =============================================================================

def _start_auto_analyze():
    """Start the background auto-analyze thread."""
    global _auto_analyze_thread, _auto_analyze_running
    
    if _auto_analyze_running:
        return
    
    _auto_analyze_running = True
    _auto_analyze_thread = threading.Thread(target=_auto_analyze_worker, daemon=True)
    _auto_analyze_thread.start()
    logger.info("Auto-analyze background worker started")


def _auto_analyze_worker():
    """Background worker that periodically analyzes new events."""
    global _auto_analyze_running
    
    while _auto_analyze_running:
        try:
            time.sleep(5)  # Check every 5 seconds
            
            with _config_lock:
                if not _global_settings["auto_analyze"] or not _providers:
                    continue
            
            provider = _get_active_provider()
            model = _get_active_model()
            
            if not provider or not context_engine.should_auto_analyze():
                continue
            
            # Get unprocessed events
            events = context_engine.get_unprocessed_events()
            if not events:
                continue
            
            # Only analyze if there are meaningful events (skip noise)
            meaningful = [
                e for e in events
                if e.get("event_type") not in ("connection",)  # Skip connection events alone
            ]
            if not meaningful:
                context_engine.mark_analyzed()
                continue
            
            # Build event context
            event_context = context_engine.build_event_context(events)
            
            # Send to AI for analysis
            messages = [
                {"role": "user", "content": f"{AUTO_ANALYZE_PROMPT}\n\n{event_context}"}
            ]
            
            response = provider.chat(
                messages=messages,
                system_prompt=SYSTEM_PROMPT,
                model=model,
                max_tokens=1024,
                temperature=0.2,
            )
            
            if not response.error and response.content:
                usage_tracker.record(response.usage)
                
                insight = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "type": "auto_analysis",
                    "content": response.content,
                    "actions": response.actions,
                    "insights": response.insights,
                    "event_count": len(events),
                    "usage": {
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                        "cost_usd": response.usage.estimated_cost_usd,
                    }
                }
                
                # Store insight for all active projects
                # (In practice, events should be project-scoped)
                for project_id in _chat_history.keys():
                    if project_id not in _auto_insights:
                        _auto_insights[project_id] = []
                    _auto_insights[project_id].append(insight)
                    
                    # Keep manageable
                    if len(_auto_insights[project_id]) > 50:
                        _auto_insights[project_id] = _auto_insights[project_id][-50:]
            
            context_engine.mark_analyzed()
            
        except Exception as e:
            logger.error(f"Auto-analyze error: {e}")
            time.sleep(10)  # Back off on error
