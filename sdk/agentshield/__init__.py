"""
AgentShield SDK — Runtime protection for AI agents.

Quick start:
    import agentshield

    agentshield.init(api_key="your-key", server_url="http://localhost:8000")
    protected_agent = agentshield.protect(agent)
    result = protected_agent.run("task")
"""

from .core import AgentShield, AgentShieldConfig, init, protect, get_instance
from .interceptor import Interceptor, InterceptorEvent, EventType
from .policies.engine import PolicyEngine, PolicyAction
from .audit.logger import AuditLogger
from .realtime import RealTimeFeed, ThreatAlert, AlertSeverity
from .context import ContextAnalyzer, ContextThreatResult, ConversationContext
from .ratelimiter import RateLimiter, RateLimitConfig, RateLimitResult
from .redaction import Redactor, RedactionConfig, RedactionResult, RedactionCategory
from .metrics import MetricsCollector, MetricType

__version__ = "1.0.0"
__all__ = [
    "AgentShield",
    "AgentShieldConfig",
    "init",
    "protect",
    "get_instance",
    "Interceptor",
    "InterceptorEvent",
    "EventType",
    "PolicyEngine",
    "PolicyAction",
    "AuditLogger",
    "RealTimeFeed",
    "ThreatAlert",
    "AlertSeverity",
    "ContextAnalyzer",
    "ContextThreatResult",
    "ConversationContext",
    "RateLimiter",
    "RateLimitConfig",
    "RateLimitResult",
    "Redactor",
    "RedactionConfig",
    "RedactionResult",
    "RedactionCategory",
    "MetricsCollector",
    "MetricType",
]
