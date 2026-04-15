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
from .guardian import Guardian, ResponseAction, ThreatLevel, PlaybookRule, ResponseRecord
from .chainguard import ChainGuard, TrustLevel, AgentNode, ChainMessage
from .vault import Vault, SecretEntry, VaultToken
from .behavioral import BehavioralAnalyzer, BehaviorSignal, BehavioralFingerprint, DeviationResult
from .threatintel import ThreatIntelDB, IOC, IOCMatch, IOCType
from .explainability import Explainer, ExplanationLevel, ThreatEvidence, DecisionExplanation
from .selftest import SelfTester, SelfTestReport, TestResult

__version__ = "3.0.0"
__all__ = [
    # Core
    "AgentShield",
    "AgentShieldConfig",
    "init",
    "protect",
    "get_instance",
    # Existing
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
    # v3.0.0 — Enterprise Security Suite
    "Guardian",
    "ResponseAction",
    "ThreatLevel",
    "PlaybookRule",
    "ResponseRecord",
    "ChainGuard",
    "TrustLevel",
    "AgentNode",
    "ChainMessage",
    "Vault",
    "SecretEntry",
    "VaultToken",
    "BehavioralAnalyzer",
    "BehaviorSignal",
    "BehavioralFingerprint",
    "DeviationResult",
    "ThreatIntelDB",
    "IOC",
    "IOCMatch",
    "IOCType",
    "Explainer",
    "ExplanationLevel",
    "ThreatEvidence",
    "DecisionExplanation",
    "SelfTester",
    "SelfTestReport",
    "TestResult",
]
