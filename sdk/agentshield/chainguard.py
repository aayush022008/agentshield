"""
AgentShield ChainGuard — Multi-agent pipeline security.
Tracks trust chains, detects agent impersonation, and prevents privilege escalation across agent boundaries.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class TrustLevel(IntEnum):
    """Trust levels for agents in a pipeline."""
    TRUSTED = 0
    VERIFIED = 1
    UNVERIFIED = 2
    SUSPICIOUS = 3
    UNTRUSTED = 4


@dataclass
class AgentNode:
    """Node representing an agent in the trust chain."""
    agent_id: str
    agent_name: str
    trust_level: TrustLevel
    capabilities: List[str]
    parent_id: Optional[str]
    created_at: float
    message_count: int = 0


@dataclass
class ChainMessage:
    """A message exchanged between agents."""
    message_id: str
    from_agent: str
    to_agent: str
    content_hash: str
    timestamp: float
    trust_level: TrustLevel
    flagged: bool = False
    flag_reason: str = ""


class ChainGuard:
    """
    Multi-agent pipeline security monitor.

    Registers agents, tracks trust chains, flags suspicious messages,
    and detects privilege escalation. Thread-safe.
    """

    _SECRET = "agentshield-chainguard-v1"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._agents: Dict[str, AgentNode] = {}
        self._messages: List[ChainMessage] = []
        self._flags: Dict[str, str] = {}  # agent_id -> reason

    def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        trust_level: TrustLevel = TrustLevel.UNVERIFIED,
        capabilities: Optional[List[str]] = None,
        parent_id: Optional[str] = None,
    ) -> AgentNode:
        """Register a new agent in the chain."""
        node = AgentNode(
            agent_id=agent_id,
            agent_name=agent_name,
            trust_level=trust_level,
            capabilities=capabilities or [],
            parent_id=parent_id,
            created_at=time.time(),
        )
        with self._lock:
            self._agents[agent_id] = node
        return node

    def verify_agent(self, agent_id: str, verification_token: str) -> bool:
        """
        Verify an agent using its token (sha256(agent_id + secret)).

        Returns True if verification succeeded.
        """
        expected = hashlib.sha256(f"{agent_id}{self._SECRET}".encode()).hexdigest()
        if verification_token == expected:
            with self._lock:
                if agent_id in self._agents:
                    self._agents[agent_id].trust_level = TrustLevel.VERIFIED
            return True
        return False

    def send_message(self, from_agent: str, to_agent: str, content: str) -> ChainMessage:
        """Record a message between agents and check trust."""
        content_hash = self._hash_content(content)
        with self._lock:
            from_node = self._agents.get(from_agent)
            trust = from_node.trust_level if from_node else TrustLevel.UNTRUSTED

            flagged = False
            flag_reason = ""
            if trust >= TrustLevel.SUSPICIOUS:
                flagged = True
                flag_reason = f"Sender trust level: {trust.name}"

            msg = ChainMessage(
                message_id=str(uuid.uuid4()),
                from_agent=from_agent,
                to_agent=to_agent,
                content_hash=content_hash,
                timestamp=time.time(),
                trust_level=trust,
                flagged=flagged,
                flag_reason=flag_reason,
            )
            self._messages.append(msg)
            if from_node:
                from_node.message_count += 1
        return msg

    def check_privilege_escalation(self, from_agent: str, to_agent: str, requested_capability: str) -> bool:
        """
        Check if sending agent is requesting a capability it doesn't have.

        Returns True if escalation detected.
        """
        with self._lock:
            from_node = self._agents.get(from_agent)
            to_node = self._agents.get(to_agent)
            if from_node is None or to_node is None:
                return True  # Unknown agents = suspicious
            if requested_capability in from_node.capabilities:
                return False
            # Escalation: requesting cap not in own list
            return True

    def get_chain(self, agent_id: str) -> List[AgentNode]:
        """Return the full trust chain from root to agent."""
        with self._lock:
            chain = []
            current_id: Optional[str] = agent_id
            seen = set()
            while current_id and current_id not in seen:
                seen.add(current_id)
                node = self._agents.get(current_id)
                if node is None:
                    break
                chain.insert(0, node)
                current_id = node.parent_id
        return chain

    def get_trust_score(self, agent_id: str) -> int:
        """Return a 0-100 trust score for an agent."""
        with self._lock:
            node = self._agents.get(agent_id)
            if node is None:
                return 0
            base_scores = {
                TrustLevel.TRUSTED: 100,
                TrustLevel.VERIFIED: 80,
                TrustLevel.UNVERIFIED: 50,
                TrustLevel.SUSPICIOUS: 20,
                TrustLevel.UNTRUSTED: 0,
            }
            score = base_scores[node.trust_level]
            # Penalize for flagged messages
            flagged = sum(1 for m in self._messages if m.from_agent == agent_id and m.flagged)
            score = max(0, score - flagged * 10)
        return score

    def flag_agent(self, agent_id: str, reason: str) -> None:
        """Mark an agent as suspicious."""
        with self._lock:
            self._flags[agent_id] = reason
            if agent_id in self._agents:
                self._agents[agent_id].trust_level = TrustLevel.SUSPICIOUS

    def get_message_history(self, agent_id: Optional[str] = None, limit: int = 100) -> List[ChainMessage]:
        """Return message history, optionally filtered by agent."""
        with self._lock:
            msgs = self._messages
            if agent_id:
                msgs = [m for m in msgs if m.from_agent == agent_id or m.to_agent == agent_id]
            return msgs[-limit:]

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()
