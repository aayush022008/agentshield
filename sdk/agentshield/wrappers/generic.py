"""
Generic agent wrapper for AgentShield v2.0.0

Wraps any agent object by intercepting common method calls.
Works with any agent that implements run(), invoke(), chat(), or __call__().

v2.0.0 additions:
- Input scanning BEFORE calling the agent (critical fix)
- Output scanning AFTER agent returns (API keys, PII, credentials)
- Velocity limiting (default: 5 suspicious queries in 60s)
- Multi-turn context accumulation
- on_audit callback (fires on every scan)
- throw_on_block config option
- reset_session() method
- scan_output() convenience method
"""

from __future__ import annotations

import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ── Output scanning patterns ──────────────────────────────────────────────────

_OUTPUT_PATTERNS: list[tuple[str, float, re.Pattern]] = [
    ("secret_leakage", 0.95, re.compile(r'sk-[a-zA-Z0-9\-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}', re.IGNORECASE)),
    ("pii_credit_card", 0.90, re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b')),
    ("pii_ssn", 0.85, re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b')),
    ("pii_email", 0.70, re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
    ("secret_leakage", 0.88, re.compile(r'(?:password|passwd|secret|api_key|access_token|auth_token)\s*[=:]\s*\S{8,}', re.IGNORECASE)),
]


@dataclass
class AuditEvent:
    timestamp: float
    session_id: str
    direction: str  # "input" or "output"
    text: str
    decision: str  # "allow", "alert", "block"
    score: float = 0.0
    reason: str = ""


def _extract_strings(obj: Any, depth: int = 0) -> list[str]:
    """Recursively extract all string values from dicts, lists, tuples."""
    if depth > 10:
        return []
    results = []
    if isinstance(obj, str):
        results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_extract_strings(v, depth + 1))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            results.extend(_extract_strings(item, depth + 1))
    return results


def _scan_output_text(text: str) -> tuple[str, float, str]:
    """Scan output text for secrets/PII. Returns (action, score, reason)."""
    matches = []
    for label, confidence, pattern in _OUTPUT_PATTERNS:
        if pattern.search(text):
            matches.append((label, confidence))
    if not matches:
        return "allow", 0.0, ""
    max_score = max(c for _, c in matches)
    reason = " | ".join(f"{l} ({c:.0%})" for l, c in matches[:3])
    action = "block" if max_score >= 0.85 else "alert"
    return action, max_score, reason


class BlockedError(Exception):
    """Raised when throw_on_block is True and input/output is blocked."""
    def __init__(self, message: str, direction: str = "input"):
        super().__init__(message)
        self.direction = direction


class GenericWrapper:
    """
    Generic wrapper that intercepts common agent methods.

    Wraps: run(), invoke(), chat(), generate(), complete(), __call__()
    """

    BLOCK_MESSAGE = "[AgentFortress] Request blocked: potential security threat detected."
    OUTPUT_BLOCK_MESSAGE = "[AgentFortress] Output blocked: sensitive data detected."

    def __init__(
        self,
        agent: Any,
        interceptor: Any,
        agent_name: str = "agent",
        on_audit: Optional[Callable[[AuditEvent], None]] = None,
        throw_on_block: bool = False,
        velocity_limit: int = 5,
        velocity_window: int = 60,
        block_threshold: float = 0.70,
        alert_threshold: float = 0.35,
    ) -> None:
        self._agent = agent
        self._interceptor = interceptor
        self._agent_name = agent_name
        self._session_id = str(uuid.uuid4())
        self._on_audit = on_audit
        self._throw_on_block = throw_on_block
        self._velocity_limit = velocity_limit
        self._velocity_window = velocity_window
        self._block_threshold = block_threshold
        self._alert_threshold = alert_threshold

        # Session state
        self._suspicious_timestamps: deque = deque()
        self._session_threat_score: float = 0.0
        self._turn_count: int = 0

        # Lazy-load scanner
        self._scanner = None

    def _get_scanner(self):
        if self._scanner is None:
            from ..scanner.advanced import AdvancedScanner
            self._scanner = AdvancedScanner(
                block_threshold=self._block_threshold,
                alert_threshold=self._alert_threshold,
            )
        return self._scanner

    def reset_session(self) -> None:
        """Clear accumulated session context, threat scores, and velocity counters."""
        self._session_id = str(uuid.uuid4())
        self._suspicious_timestamps.clear()
        self._session_threat_score = 0.0
        self._turn_count = 0

    def scan_output(self, text: str) -> tuple[str, float, str]:
        """Convenience method: scan output text for PII/secrets. Returns (action, score, reason)."""
        action, score, reason = _scan_output_text(text)
        self._fire_audit(AuditEvent(
            timestamp=time.time(),
            session_id=self._session_id,
            direction="output",
            text=text[:500],
            decision=action,
            score=score,
            reason=reason,
        ))
        return action, score, reason

    def _check_velocity(self) -> bool:
        """Returns True if velocity limit exceeded (should block)."""
        now = time.time()
        # Remove old entries
        while self._suspicious_timestamps and now - self._suspicious_timestamps[0] > self._velocity_window:
            self._suspicious_timestamps.popleft()
        return len(self._suspicious_timestamps) >= self._velocity_limit

    def _record_suspicious(self) -> None:
        self._suspicious_timestamps.append(time.time())

    def _fire_audit(self, event: AuditEvent) -> None:
        if self._on_audit:
            try:
                self._on_audit(event)
            except Exception:
                pass

    def _scan_input(self, texts: list[str]) -> tuple[str, float, str]:
        """Scan all input strings. Returns worst (action, score, reason)."""
        scanner = self._get_scanner()
        worst_action = "allow"
        worst_score = 0.0
        worst_reason = ""

        for text in texts:
            if not text.strip():
                continue
            result = scanner.scan(text)

            # Boost score based on session history
            boosted_score = result.score
            if self._session_threat_score > 0 and self._turn_count > 0:
                boost = min(self._session_threat_score * 0.1, 0.20)
                boosted_score = min(result.score + boost, 1.0)

            if boosted_score > worst_score:
                worst_score = boosted_score
                worst_reason = result.reason
                if boosted_score >= self._block_threshold:
                    worst_action = "block"
                elif boosted_score >= self._alert_threshold:
                    worst_action = "alert"

        return worst_action, worst_score, worst_reason

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.run()."""
        return self._run_with_intercept("run", *args, **kwargs)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.invoke()."""
        return self._run_with_intercept("invoke", *args, **kwargs)

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.chat()."""
        return self._run_with_intercept("chat", *args, **kwargs)

    def generate(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.generate()."""
        return self._run_with_intercept("generate", *args, **kwargs)

    def complete(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.complete()."""
        return self._run_with_intercept("complete", *args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept direct agent() calls."""
        return self._run_with_intercept("__call__", *args, **kwargs)

    def _run_with_intercept(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Run the wrapped method with full interception."""
        from ..interceptor import EventType, InterceptorEvent

        self._turn_count += 1

        # ── Extract all string inputs ────────────────────────────────────────
        all_strings = []
        for a in args:
            all_strings.extend(_extract_strings(a))
        for v in kwargs.values():
            all_strings.extend(_extract_strings(v))

        # ── Check velocity limit ─────────────────────────────────────────────
        if self._check_velocity():
            msg = "[AgentFortress] Rate limit exceeded: too many suspicious queries."
            evt = AuditEvent(
                timestamp=time.time(),
                session_id=self._session_id,
                direction="input",
                text=str(all_strings)[:200],
                decision="block",
                score=1.0,
                reason="velocity_limit_exceeded",
            )
            self._fire_audit(evt)
            if self._throw_on_block:
                raise BlockedError(msg, direction="input")
            return msg

        # ── Scan inputs BEFORE calling the agent ─────────────────────────────
        if all_strings:
            action, score, reason = self._scan_input(all_strings)

            # Extract primary prompt for interceptor
            prompt = all_strings[0] if all_strings else ""

            self._interceptor.capture_llm_start(
                session_id=self._session_id,
                agent_name=self._agent_name,
                prompt=prompt,
                extra={"method": method_name},
            )

            # Update session threat state
            if score > 0:
                self._session_threat_score = (self._session_threat_score * 0.8) + (score * 0.2)
                if score >= self._alert_threshold:
                    self._record_suspicious()

            # Fire audit event
            self._fire_audit(AuditEvent(
                timestamp=time.time(),
                session_id=self._session_id,
                direction="input",
                text=prompt[:500],
                decision=action,
                score=score,
                reason=reason,
            ))

            if action == "block":
                if self._throw_on_block:
                    raise BlockedError(self.BLOCK_MESSAGE, direction="input")
                return self.BLOCK_MESSAGE
        else:
            # No strings to scan — still log start
            self._interceptor.capture_llm_start(
                session_id=self._session_id,
                agent_name=self._agent_name,
                prompt="",
                extra={"method": method_name},
            )

        # ── Call the actual agent method ─────────────────────────────────────
        start = time.monotonic()
        method = getattr(self._agent, method_name)
        result = method(*args, **kwargs)
        latency_ms = (time.monotonic() - start) * 1000

        output = str(result) if result is not None else ""
        self._interceptor.capture_llm_end(
            session_id=self._session_id,
            agent_name=self._agent_name,
            output=output,
            latency_ms=latency_ms,
        )

        # ── Scan output AFTER agent returns ──────────────────────────────────
        if output:
            out_action, out_score, out_reason = _scan_output_text(output)
            self._fire_audit(AuditEvent(
                timestamp=time.time(),
                session_id=self._session_id,
                direction="output",
                text=output[:500],
                decision=out_action,
                score=out_score,
                reason=out_reason,
            ))
            if out_action == "block":
                if self._throw_on_block:
                    raise BlockedError(self.OUTPUT_BLOCK_MESSAGE, direction="output")
                return self.OUTPUT_BLOCK_MESSAGE

        return result

    def get_session_id(self) -> str:
        """Return the session ID for this wrapped agent."""
        return self._session_id

    def kill(self) -> None:
        """Kill this agent session."""
        self._interceptor.kill_session(self._session_id)

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying agent."""
        return getattr(self._agent, name)
