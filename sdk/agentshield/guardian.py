"""
AgentShield Guardian — Autonomous threat response engine.
Automatically takes action when threats are detected based on configurable response playbooks.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ResponseAction(str, Enum):
    """Available automated response actions."""
    BLOCK = "block"
    THROTTLE = "throttle"
    SHADOW_MODE = "shadow_mode"
    QUARANTINE = "quarantine"
    ALERT_ONLY = "alert_only"
    KILL_SESSION = "kill_session"
    HONEYPOT_REDIRECT = "honeypot_redirect"


class ThreatLevel(str, Enum):
    """Threat severity levels derived from numeric score."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class PlaybookRule:
    """A single rule in a response playbook."""
    name: str
    threat_level: ThreatLevel
    response_action: ResponseAction
    cooldown_seconds: float = 60.0
    auto_escalate: bool = False
    escalate_after_n: int = 3


@dataclass
class ResponseRecord:
    """Record of a Guardian response action."""
    rule_name: str
    action_taken: ResponseAction
    session_id: str
    timestamp: float
    threat_score: int
    reason: str


def _default_playbook() -> List[PlaybookRule]:
    return [
        PlaybookRule("critical_kill", ThreatLevel.CRITICAL, ResponseAction.KILL_SESSION, auto_escalate=False),
        PlaybookRule("high_quarantine", ThreatLevel.HIGH, ResponseAction.QUARANTINE, auto_escalate=True, escalate_after_n=3),
        PlaybookRule("medium_throttle", ThreatLevel.MEDIUM, ResponseAction.THROTTLE),
        PlaybookRule("low_alert", ThreatLevel.LOW, ResponseAction.ALERT_ONLY),
    ]


class Guardian:
    """
    Autonomous threat response engine.

    Evaluates threat scores and automatically applies security responses
    based on a configurable playbook. Thread-safe.
    """

    def __init__(self, playbook: Optional[List[PlaybookRule]] = None) -> None:
        self._playbook = playbook if playbook is not None else _default_playbook()
        self._lock = threading.Lock()
        # session_id -> {"quarantined": bool, "throttled": bool, "strikes": int}
        self._session_state: Dict[str, dict] = {}
        self._history: List[ResponseRecord] = []

    def _get_threat_level(self, score: int) -> ThreatLevel:
        if score >= 90:
            return ThreatLevel.CRITICAL
        elif score >= 70:
            return ThreatLevel.HIGH
        elif score >= 50:
            return ThreatLevel.MEDIUM
        elif score >= 30:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE

    def _get_rule(self, level: ThreatLevel) -> Optional[PlaybookRule]:
        for rule in self._playbook:
            if rule.threat_level == level:
                return rule
        return None

    def evaluate(self, session_id: str, threat_score: int, event_type: str, reason: str) -> ResponseAction:
        """
        Evaluate a threat event and return the appropriate response action.

        Args:
            session_id: Unique session identifier.
            threat_score: Numeric threat score (0-100).
            event_type: Type of event (e.g., 'llm_start').
            reason: Human-readable reason for the threat.

        Returns:
            ResponseAction to take.
        """
        level = self._get_threat_level(threat_score)
        rule = self._get_rule(level)

        if rule is None or level == ThreatLevel.SAFE:
            return ResponseAction.ALERT_ONLY

        with self._lock:
            state = self._session_state.setdefault(session_id, {"quarantined": False, "throttled": False, "strikes": 0})
            action = rule.response_action

            if rule.response_action == ResponseAction.QUARANTINE:
                state["strikes"] += 1
                state["quarantined"] = True
                if rule.auto_escalate and state["strikes"] >= rule.escalate_after_n:
                    action = ResponseAction.KILL_SESSION
            elif rule.response_action == ResponseAction.THROTTLE:
                state["throttled"] = True
            elif rule.response_action == ResponseAction.KILL_SESSION:
                state["quarantined"] = True
                state["throttled"] = True

            record = ResponseRecord(
                rule_name=rule.name,
                action_taken=action,
                session_id=session_id,
                timestamp=time.time(),
                threat_score=threat_score,
                reason=reason,
            )
            self._history.append(record)

        return action

    def get_session_status(self, session_id: str) -> dict:
        """Return current quarantine/throttle status for a session."""
        with self._lock:
            return dict(self._session_state.get(session_id, {"quarantined": False, "throttled": False, "strikes": 0}))

    def is_quarantined(self, session_id: str) -> bool:
        return self.get_session_status(session_id).get("quarantined", False)

    def is_throttled(self, session_id: str) -> bool:
        return self.get_session_status(session_id).get("throttled", False)

    def release(self, session_id: str) -> None:
        """Manually release a session from quarantine/throttle."""
        with self._lock:
            if session_id in self._session_state:
                self._session_state[session_id]["quarantined"] = False
                self._session_state[session_id]["throttled"] = False

    def get_response_history(self, session_id: Optional[str] = None) -> List[ResponseRecord]:
        """Return response history, optionally filtered by session."""
        with self._lock:
            if session_id:
                return [r for r in self._history if r.session_id == session_id]
            return list(self._history)
