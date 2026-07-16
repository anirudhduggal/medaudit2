"""
AI Provider Abstraction Layer

Supports multiple AI backends:
- Anthropic Claude (cloud)
- OpenAI (cloud)
- OpenRouter (cloud gateway to many models)
- Google Gemini (cloud)
- Ollama (local)

Each provider implements the same interface for chat completion,
model listing, and key validation.
"""

import time
import logging
import threading
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TokenUsage:
    """Track token usage for a single request."""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    timestamp: float = field(default_factory=time.time)
    
    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens
    
    @property
    def estimated_cost_usd(self) -> float:
        """Estimate cost based on model pricing across all providers."""
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING.get("default"))
        if not pricing:
            return 0.0
        input_cost = (self.input_tokens / 1_000_000) * pricing["input"]
        output_cost = (self.output_tokens / 1_000_000) * pricing["output"]
        return round(input_cost + output_cost, 6)


@dataclass
class AIResponse:
    """Standardized response from any AI provider."""
    content: str
    model: str
    usage: TokenUsage
    actions: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "model": self.model,
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "total_tokens": self.usage.total_tokens,
                "estimated_cost_usd": self.usage.estimated_cost_usd,
            },
            "actions": self.actions,
            "insights": self.insights,
            "error": self.error,
        }


# Pricing per million tokens across all providers
MODEL_PRICING = {
    # Anthropic
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
    "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.0},
    "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
    "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},
    # OpenAI
    "gpt-4o": {"input": 2.50, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.0, "output": 30.0},
    "gpt-4": {"input": 30.0, "output": 60.0},
    "o1": {"input": 15.0, "output": 60.0},
    "o1-mini": {"input": 1.10, "output": 4.40},
    "o3-mini": {"input": 1.10, "output": 4.40},
    # Google Gemini
    "gemini-2.5-pro-preview-06-05": {"input": 1.25, "output": 10.0},
    "gemini-2.5-flash-preview-05-20": {"input": 0.15, "output": 0.60},
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.0},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    # Default fallback
    "default": {"input": 3.0, "output": 15.0},
}

# Provider display metadata
PROVIDER_INFO = {
    "anthropic": {
        "name": "Anthropic Claude",
        "icon": "bi-cpu",
        "key_placeholder": "sk-ant-api03-...",
        "docs_url": "https://console.anthropic.com/settings/keys",
    },
    "openai": {
        "name": "OpenAI",
        "icon": "bi-openai",
        "key_placeholder": "sk-proj-...",
        "docs_url": "https://platform.openai.com/api-keys",
    },
    "openrouter": {
        "name": "OpenRouter",
        "icon": "bi-diagram-3",
        "key_placeholder": "sk-or-v1-...",
        "docs_url": "https://openrouter.ai/keys",
    },
    "gemini": {
        "name": "Google Gemini",
        "icon": "bi-google",
        "key_placeholder": "AIza...",
        "docs_url": "https://aistudio.google.com/apikey",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "icon": "bi-pc-display",
        "key_placeholder": "Not required",
        "docs_url": "https://ollama.com",
    },
}


# =============================================================================
# Shared helpers for extracting structured data from AI responses
# =============================================================================

def _extract_actions_from_content(content: str) -> List[Dict[str, Any]]:
    """Extract executable action suggestions from AI response."""
    import re, json
    actions = []
    pattern = r'\[ACTION:(\w+)\](.*?)\[/ACTION\]'
    for action_type, action_data in re.findall(pattern, content, re.DOTALL):
        try:
            data = json.loads(action_data.strip())
            actions.append({"type": action_type, "data": data, "label": data.get("label", f"Execute: {action_type}")})
        except (json.JSONDecodeError, ValueError):
            actions.append({"type": action_type, "data": {"raw": action_data.strip()}, "label": f"Execute: {action_type}"})
    return actions


def _extract_insights_from_content(content: str) -> List[str]:
    """Extract key insights from AI response."""
    import re
    return [m.strip() for m in re.findall(r'\[INSIGHT\](.*?)\[/INSIGHT\]', content, re.DOTALL) if m.strip()]


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    @abstractmethod
    def validate_key(self) -> Tuple[bool, Optional[str]]:
        """
        Validate the API key.
        Returns: (is_valid, error_message or None)
        """
        pass
    
    @abstractmethod
    def list_models(self) -> List[Dict[str, str]]:
        """
        List available models.
        Returns: List of {"id": "model-id", "name": "Display Name"}
        """
        pass
    
    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: str,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> AIResponse:
        """
        Send a chat completion request.
        
        Args:
            messages: List of {"role": "user"|"assistant", "content": "..."}
            system_prompt: System instructions
            model: Model identifier
            max_tokens: Maximum tokens in response
            temperature: Creativity (0.0 = deterministic, 1.0 = creative)
            
        Returns: AIResponse with content and usage
        """
        pass
    
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name."""
        pass


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = None
    
    def _get_client(self):
        """Lazy-initialize the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise RuntimeError(
                    "anthropic package not installed. Run: pip install anthropic"
                )
        return self._client
    
    def provider_name(self) -> str:
        return "anthropic"
    
    def validate_key(self) -> Tuple[bool, Optional[str]]:
        """Validate the Anthropic API key by making a minimal request."""
        try:
            client = self._get_client()
            # Use a minimal message to validate
            response = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "hi"}],
            )
            return True, None
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "authentication" in error_msg.lower():
                return False, "Invalid API key"
            elif "403" in error_msg or "permission" in error_msg.lower():
                return False, "API key lacks required permissions"
            elif "429" in error_msg:
                return False, "Rate limited - key is valid but being throttled"
            else:
                return False, f"Validation failed: {error_msg}"
    
    def list_models(self) -> List[Dict[str, str]]:
        """List available Anthropic Claude models."""
        try:
            client = self._get_client()
            response = client.models.list()
            
            models = []
            for model in response.data:
                models.append({
                    "id": model.id,
                    "name": model.display_name if hasattr(model, 'display_name') else model.id,
                })
            
            # Sort by name
            models.sort(key=lambda m: m["name"])
            return models
            
        except Exception as e:
            logger.warning(f"Failed to fetch models from API: {e}")
            # Fallback to known models
            return [
                {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4"},
                {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet"},
                {"id": "claude-3-5-haiku-20241022", "name": "Claude 3.5 Haiku"},
                {"id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku"},
                {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus"},
            ]
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: str,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> AIResponse:
        """Send a message to Claude and get a response."""
        try:
            client = self._get_client()
            
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=messages,
            )
            
            content = response.content[0].text if response.content else ""
            
            usage = TokenUsage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                model=model,
            )
            
            # Parse actions from response (look for structured action blocks)
            actions = self._extract_actions(content)
            insights = self._extract_insights(content)
            
            return AIResponse(
                content=content,
                model=model,
                usage=usage,
                actions=actions,
                insights=insights,
            )
            
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return AIResponse(
                content="",
                model=model,
                usage=TokenUsage(model=model),
                error=str(e),
            )
    
    def _extract_actions(self, content: str) -> List[Dict[str, Any]]:
        return _extract_actions_from_content(content)
    
    def _extract_insights(self, content: str) -> List[str]:
        return _extract_insights_from_content(content)


class OpenAIProvider(AIProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = None
    
    def _get_client(self):
        if self._client is None:
            try:
                import openai
                self._client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                raise RuntimeError("openai package not installed. Run: pip install openai")
        return self._client
    
    def provider_name(self) -> str:
        return "openai"
    
    def validate_key(self) -> Tuple[bool, Optional[str]]:
        try:
            client = self._get_client()
            client.models.list()
            return True, None
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "invalid" in error_msg.lower():
                return False, "Invalid API key"
            elif "429" in error_msg:
                return False, "Rate limited - key is valid but being throttled"
            return False, f"Validation failed: {error_msg}"
    
    def list_models(self) -> List[Dict[str, str]]:
        try:
            client = self._get_client()
            response = client.models.list()
            
            # Filter to chat completion models
            chat_models = []
            for model in response.data:
                model_id = model.id
                if any(prefix in model_id for prefix in ["gpt-4", "gpt-3.5", "o1", "o3"]):
                    chat_models.append({
                        "id": model_id,
                        "name": model_id,
                    })
            
            chat_models.sort(key=lambda m: m["name"])
            return chat_models if chat_models else [
                {"id": "gpt-4o", "name": "GPT-4o"},
                {"id": "gpt-4o-mini", "name": "GPT-4o Mini"},
            ]
        except Exception as e:
            logger.warning(f"Failed to fetch OpenAI models: {e}")
            return [
                {"id": "gpt-4o", "name": "GPT-4o"},
                {"id": "gpt-4o-mini", "name": "GPT-4o Mini"},
                {"id": "gpt-4-turbo", "name": "GPT-4 Turbo"},
                {"id": "o3-mini", "name": "o3-mini"},
            ]
    
    def chat(self, messages, system_prompt, model, max_tokens=4096, temperature=0.3) -> AIResponse:
        try:
            client = self._get_client()
            
            full_messages = [{"role": "system", "content": system_prompt}] + messages
            
            response = client.chat.completions.create(
                model=model,
                messages=full_messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            
            content = response.choices[0].message.content or ""
            usage = TokenUsage(
                input_tokens=response.usage.prompt_tokens if response.usage else 0,
                output_tokens=response.usage.completion_tokens if response.usage else 0,
                model=model,
            )
            
            actions = self._extract_actions(content)
            insights = self._extract_insights(content)
            
            return AIResponse(content=content, model=model, usage=usage, actions=actions, insights=insights)
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return AIResponse(content="", model=model, usage=TokenUsage(model=model), error=str(e))
    
    def _extract_actions(self, content: str) -> List[Dict[str, Any]]:
        return _extract_actions_from_content(content)
    
    def _extract_insights(self, content: str) -> List[str]:
        return _extract_insights_from_content(content)


class OpenRouterProvider(OpenAIProvider):
    """
    OpenRouter provider.

    OpenRouter is an OpenAI-API-compatible gateway that fronts hundreds of
    models from many vendors behind a single key. We reuse OpenAIProvider's
    chat()/validate_key() and only override client construction (different
    base URL) and model listing (OpenRouter ids contain a vendor prefix,
    e.g. "anthropic/claude-sonnet-4", so the gpt-* filter does not apply).
    """

    BASE_URL = "https://openrouter.ai/api/v1"

    def _get_client(self):
        if self._client is None:
            try:
                import openai
                self._client = openai.OpenAI(
                    api_key=self.api_key,
                    base_url=self.BASE_URL,
                    # Optional attribution headers used by OpenRouter dashboards.
                    default_headers={
                        "HTTP-Referer": "https://github.com/anirudhduggal/medaudit2",
                        "X-Title": "medaudit2",
                    },
                )
            except ImportError:
                raise RuntimeError("openai package not installed. Run: pip install openai")
        return self._client

    def provider_name(self) -> str:
        return "openrouter"

    def list_models(self) -> List[Dict[str, str]]:
        """List every model OpenRouter exposes (sorted by id)."""
        try:
            client = self._get_client()
            response = client.models.list()
            models = []
            for model in response.data:
                model_id = model.id
                name = getattr(model, "name", None) or model_id
                models.append({"id": model_id, "name": name})
            models.sort(key=lambda m: m["id"])
            return models if models else [
                {"id": "openrouter/auto", "name": "Auto (best available)"},
            ]
        except Exception as e:
            logger.warning(f"Failed to fetch OpenRouter models: {e}")
            return [{"id": "openrouter/auto", "name": "Auto (best available)"}]


class GeminiProvider(AIProvider):
    """Google Gemini provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = None
    
    def _get_client(self):
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except ImportError:
                raise RuntimeError("google-genai package not installed. Run: pip install google-genai")
        return self._client
    
    def provider_name(self) -> str:
        return "gemini"
    
    def validate_key(self) -> Tuple[bool, Optional[str]]:
        try:
            client = self._get_client()
            list(client.models.list())
            return True, None
        except Exception as e:
            error_msg = str(e)
            if "400" in error_msg or "invalid" in error_msg.lower() or "API_KEY" in error_msg:
                return False, "Invalid API key"
            return False, f"Validation failed: {error_msg}"
    
    def list_models(self) -> List[Dict[str, str]]:
        try:
            client = self._get_client()
            models = []
            for model in client.models.list():
                model_id = model.name
                # Gemini API returns "models/gemini-..." format
                if model_id.startswith("models/"):
                    model_id = model_id[7:]
                if "gemini" in model_id:
                    display = model.display_name if hasattr(model, 'display_name') and model.display_name else model_id
                    models.append({"id": model_id, "name": display})
            
            models.sort(key=lambda m: m["name"])
            return models if models else self._fallback_models()
        except Exception as e:
            logger.warning(f"Failed to fetch Gemini models: {e}")
            return self._fallback_models()
    
    def _fallback_models(self):
        return [
            {"id": "gemini-2.5-flash-preview-05-20", "name": "Gemini 2.5 Flash"},
            {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash"},
            {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro"},
            {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash"},
        ]
    
    def chat(self, messages, system_prompt, model, max_tokens=4096, temperature=0.3) -> AIResponse:
        try:
            client = self._get_client()
            from google.genai import types
            
            # Convert messages to Gemini format
            gemini_contents = []
            for msg in messages:
                role = "user" if msg["role"] == "user" else "model"
                gemini_contents.append(types.Content(
                    role=role,
                    parts=[types.Part(text=msg["content"])]
                ))
            
            response = client.models.generate_content(
                model=model,
                contents=gemini_contents,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=max_tokens,
                    temperature=temperature,
                ),
            )
            
            content = response.text or ""
            
            # Extract usage
            input_tokens = 0
            output_tokens = 0
            if hasattr(response, 'usage_metadata') and response.usage_metadata:
                input_tokens = getattr(response.usage_metadata, 'prompt_token_count', 0) or 0
                output_tokens = getattr(response.usage_metadata, 'candidates_token_count', 0) or 0
            
            usage = TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens, model=model)
            actions = _extract_actions_from_content(content)
            insights = _extract_insights_from_content(content)
            
            return AIResponse(content=content, model=model, usage=usage, actions=actions, insights=insights)
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return AIResponse(content="", model=model, usage=TokenUsage(model=model), error=str(e))


class OllamaProvider(AIProvider):
    """Ollama local model provider."""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
    
    def provider_name(self) -> str:
        return "ollama"
    
    def validate_key(self) -> Tuple[bool, Optional[str]]:
        """Validate Ollama is reachable."""
        try:
            import urllib.request
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return True, None
            return False, "Ollama not responding"
        except Exception as e:
            return False, f"Cannot connect to Ollama at {self.base_url}: {str(e)}"
    
    def list_models(self) -> List[Dict[str, str]]:
        """List available Ollama models."""
        try:
            import urllib.request
            import json
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return [
                    {"id": m["name"], "name": m["name"]}
                    for m in data.get("models", [])
                ]
        except Exception:
            return []
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: str,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> AIResponse:
        """Send a chat request to Ollama."""
        try:
            import urllib.request
            import json
            
            # Prepend system prompt as a system message
            full_messages = [{"role": "system", "content": system_prompt}] + messages
            
            payload = json.dumps({
                "model": model,
                "messages": full_messages,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                }
            }).encode()
            
            req = urllib.request.Request(
                f"{self.base_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
            
            content = data.get("message", {}).get("content", "")
            
            # Ollama provides eval_count and prompt_eval_count
            usage = TokenUsage(
                input_tokens=data.get("prompt_eval_count", 0),
                output_tokens=data.get("eval_count", 0),
                model=model,
            )
            
            actions = _extract_actions_from_content(content)
            insights = _extract_insights_from_content(content)
            
            return AIResponse(
                content=content,
                model=model,
                usage=usage,
                actions=actions,
                insights=insights,
            )
            
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            return AIResponse(
                content="",
                model=model,
                usage=TokenUsage(model=model),
                error=str(e),
            )


# =============================================================================
# Token Usage Tracker (Session-wide)
# =============================================================================

class UsageTracker:
    """Track cumulative token usage and costs across a session."""
    
    def __init__(self):
        self._history: List[TokenUsage] = []
        self._lock = threading.Lock()
    
    def record(self, usage: TokenUsage):
        """Record a usage entry."""
        with self._lock:
            self._history.append(usage)
    
    def get_session_totals(self) -> Dict[str, Any]:
        """Get cumulative totals for the current session."""
        with self._lock:
            total_input = sum(u.input_tokens for u in self._history)
            total_output = sum(u.output_tokens for u in self._history)
            total_cost = sum(u.estimated_cost_usd for u in self._history)
            
            return {
                "total_requests": len(self._history),
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "total_tokens": total_input + total_output,
                "total_cost_usd": round(total_cost, 6),
                "history": [
                    {
                        "model": u.model,
                        "input_tokens": u.input_tokens,
                        "output_tokens": u.output_tokens,
                        "cost_usd": u.estimated_cost_usd,
                        "timestamp": u.timestamp,
                    }
                    for u in self._history[-20:]  # Last 20 entries
                ]
            }
    
    def reset(self):
        """Reset usage tracking."""
        with self._lock:
            self._history.clear()


# Global usage tracker
usage_tracker = UsageTracker()


# =============================================================================
# Provider Factory
# =============================================================================

def get_provider(
    provider_type: str,
    api_key: str = None,
    base_url: str = None,
) -> AIProvider:
    """
    Factory function to get an AI provider.

    Args:
        provider_type: "anthropic", "openai", "gemini", or "ollama"
        api_key: API key (required for cloud providers)
        base_url: Base URL (for ollama, defaults to localhost:11434)

    Returns: AIProvider instance
    """
    if provider_type == "anthropic":
        if not api_key:
            raise ValueError("API key is required for Anthropic")
        return AnthropicProvider(api_key=api_key)

    elif provider_type == "openai":
        if not api_key:
            raise ValueError("API key is required for OpenAI")
        return OpenAIProvider(api_key=api_key)

    elif provider_type == "openrouter":
        if not api_key:
            raise ValueError("API key is required for OpenRouter")
        return OpenRouterProvider(api_key=api_key)

    elif provider_type == "gemini":
        if not api_key:
            raise ValueError("API key is required for Google Gemini")
        return GeminiProvider(api_key=api_key)

    elif provider_type == "ollama":
        url = base_url or "http://localhost:11434"
        return OllamaProvider(base_url=url)

    else:
        raise ValueError(f"Unknown provider: {provider_type}. Supported: anthropic, openai, openrouter, gemini, ollama")
