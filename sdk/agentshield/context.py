"""
AgentShield context-aware threat scoring.

Tracks conversation history per session and detects escalation patterns,
topic pivots, and chains of concern across multiple turns.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


BENIGN_TOPICS: Set[str] = {"weather", "cooking", "travel", "sports"}
SENSITIVE_TOPICS: Set[str] = {
    "hacking", "malware", "weapons", "exploits",
    "bypass", "jailbreak", "injection",
}


@dataclass
class ContextThreatResult:
    """Result of a context-aware threat analysis."""
    context_score: int  # 0-100
    escalation_detected: bool
    pivot_detected: bool
    chain_of_concern: List[str]


@dataclass
class ConversationContext:
    """Holds conversation history for a session."""
    session_id: str
    turns: List[dict] = field(default_factory=list)
    topics_seen: Set[str] = field(default_factory=set)
    tools_used: List[str] = field(default_factory=list)
    threat_scores: List[int] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)


class ContextAnalyzer:
    """
    Analyzes conversation context to detect escalation and topic pivots.

    Maintains per-session ConversationContext and applies heuristic detection
    using keyword sets and sliding window scoring.
    """

    _WINDOW_SIZE = 20

    def __init__(self) -> None:
        self._sessions: Dict[str, ConversationContext] = {}

    def _get_or_create(self, session_id: str) -> ConversationContext:
        if session_id not in self._sessions:
            self._sessions[session_id] = ConversationContext(session_id=session_id)
        return self._sessions[session_id]

    def update(
        self,
        session_id: str,
        role: str,
        content: str,
        threat_score: int = 0,
        tool_name: Optional[str] = None,
    ) -> None:
        """
        Add a new turn to the session context.

        Args:
            session_id: Session identifier.
            role: Speaker role (e.g., 'user', 'assistant').
            content: Message content.
            threat_score: Threat score for this turn (0-100).
            tool_name: Name of tool called, if any.
        """
        ctx = self._get_or_create(session_id)

        # Detect topics in content
        lower = content.lower()
        for topic in BENIGN_TOPICS | SENSITIVE_TOPICS:
            if topic in lower:
                ctx.topics_seen.add(topic)

        turn = {
            "role": role,
            "content": content,
            "threat_score": threat_score,
            "tool_name": tool_name,
            "timestamp": time.time(),
        }
        ctx.turns.append(turn)
        ctx.threat_scores.append(threat_score)
        if tool_name:
            ctx.tools_used.append(tool_name)

        # Sliding window: keep last 20 turns
        if len(ctx.turns) > self._WINDOW_SIZE:
            ctx.turns = ctx.turns[-self._WINDOW_SIZE:]
            ctx.threat_scores = ctx.threat_scores[-self._WINDOW_SIZE:]

    def analyze(self, session_id: str) -> ContextThreatResult:
        """
        Analyze session context for threats.

        Args:
            session_id: Session identifier.

        Returns:
            ContextThreatResult with scores and flags.
        """
        if session_id not in self._sessions:
            return ContextThreatResult(
                context_score=0,
                escalation_detected=False,
                pivot_detected=False,
                chain_of_concern=[],
            )

        ctx = self._sessions[session_id]
        chain: List[str] = []
        escalation = False
        pivot = False

        # Escalation: last 3 threat scores strictly increasing
        scores = ctx.threat_scores
        if len(scores) >= 3:
            last3 = scores[-3:]
            if last3[0] < last3[1] < last3[2]:
                escalation = True
                chain.append(
                    f"Escalating threat scores over last 3 turns: {last3}"
                )

        # Topic pivot: benign topics seen AND sensitive topics seen
        has_benign = bool(ctx.topics_seen & BENIGN_TOPICS)
        has_sensitive = bool(ctx.topics_seen & SENSITIVE_TOPICS)
        if has_benign and has_sensitive:
            pivot = True
            benign_found = ctx.topics_seen & BENIGN_TOPICS
            sensitive_found = ctx.topics_seen & SENSITIVE_TOPICS
            chain.append(
                f"Topic pivot detected: benign={benign_found}, sensitive={sensitive_found}"
            )

        # Sensitive topics without benign context
        if has_sensitive and not has_benign:
            chain.append(
                f"Sensitive topics detected: {ctx.topics_seen & SENSITIVE_TOPICS}"
            )

        # High tool diversity
        unique_tools = len(set(ctx.tools_used))
        if unique_tools >= 5:
            chain.append(f"High tool diversity: {unique_tools} unique tools used")

        # Compute context score (weighted)
        base_score = max(scores[-5:]) if scores else 0  # max of last 5 scores
        escalation_bonus = 20 if escalation else 0
        pivot_bonus = 25 if pivot else 0
        avg_score = sum(scores) / len(scores) if scores else 0

        context_score = min(100, int(avg_score * 0.4 + base_score * 0.3 + escalation_bonus + pivot_bonus))

        return ContextThreatResult(
            context_score=context_score,
            escalation_detected=escalation,
            pivot_detected=pivot,
            chain_of_concern=chain,
        )

    def clear_session(self, session_id: str) -> None:
        """Remove all context for a session."""
        self._sessions.pop(session_id, None)

    def get_session_risk(self, session_id: str) -> int:
        """
        Get the current risk score for a session (0-100).

        Args:
            session_id: Session identifier.

        Returns:
            Integer risk score.
        """
        return self.analyze(session_id).context_score
