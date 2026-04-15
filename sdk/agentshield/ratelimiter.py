"""
AgentShield sliding-window rate limiter.

Provides per-session and per-agent rate limiting using a sliding window
algorithm with configurable burst capacity.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    retry_after_seconds: float
    reason: str
    current_count: int
    limit: int


@dataclass
class RateLimitConfig:
    """Configuration for the rate limiter."""
    requests_per_minute: int = 60
    burst_multiplier: float = 1.5
    window_seconds: float = 60.0


class RateLimiter:
    """
    Thread-safe sliding window rate limiter.

    Enforces per-session and per-agent limits. Uses a list of timestamps
    to track requests within the sliding window.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None) -> None:
        self._config = config or RateLimitConfig()
        self._lock = threading.Lock()
        # key → list of request timestamps
        self._windows: Dict[str, List[float]] = {}

    def _get_limit(self) -> int:
        """Return the burst-adjusted limit."""
        return int(self._config.requests_per_minute * self._config.burst_multiplier)

    def _cleanup_window(self, key: str, now: float) -> List[float]:
        """Remove expired timestamps and return the current window."""
        cutoff = now - self._config.window_seconds
        window = self._windows.get(key, [])
        window = [ts for ts in window if ts >= cutoff]
        self._windows[key] = window
        return window

    def check_and_consume(
        self,
        session_id: str,
        agent_name: str = "",
        tokens: int = 1,
    ) -> RateLimitResult:
        """
        Check rate limit and consume tokens if allowed.

        Checks both session and agent keys (if agent_name provided).
        The more restrictive limit applies.

        Args:
            session_id: Session identifier.
            agent_name: Agent identifier (optional).
            tokens: Number of tokens to consume.

        Returns:
            RateLimitResult indicating whether the request is allowed.
        """
        limit = self._get_limit()
        now = time.time()

        with self._lock:
            # Check session limit
            session_window = self._cleanup_window(session_id, now)
            session_count = len(session_window)

            if session_count + tokens > limit:
                oldest = session_window[0] if session_window else now
                retry_after = (oldest + self._config.window_seconds) - now
                return RateLimitResult(
                    allowed=False,
                    retry_after_seconds=max(0.0, retry_after),
                    reason=f"Session rate limit exceeded: {session_count}/{limit}",
                    current_count=session_count,
                    limit=limit,
                )

            # Check agent limit (if provided)
            if agent_name:
                agent_window = self._cleanup_window(agent_name, now)
                agent_count = len(agent_window)

                if agent_count + tokens > limit:
                    oldest = agent_window[0] if agent_window else now
                    retry_after = (oldest + self._config.window_seconds) - now
                    return RateLimitResult(
                        allowed=False,
                        retry_after_seconds=max(0.0, retry_after),
                        reason=f"Agent rate limit exceeded: {agent_count}/{limit}",
                        current_count=agent_count,
                        limit=limit,
                    )

            # Consume tokens
            new_timestamps = [now] * tokens
            self._windows[session_id] = session_window + new_timestamps
            if agent_name:
                self._windows[agent_name] = self._windows.get(agent_name, []) + new_timestamps

            return RateLimitResult(
                allowed=True,
                retry_after_seconds=0.0,
                reason="",
                current_count=session_count + tokens,
                limit=limit,
            )

    def get_usage_stats(self) -> dict:
        """
        Return usage statistics for all tracked keys.

        Returns:
            Dict with per-key request counts within the current window.
        """
        now = time.time()
        stats: dict = {"sessions": {}, "agents": {}}
        with self._lock:
            for key, timestamps in self._windows.items():
                cutoff = now - self._config.window_seconds
                count = sum(1 for ts in timestamps if ts >= cutoff)
                # Simple heuristic: UUIDs are session keys, others are agent keys
                if len(key) == 36 and key.count("-") == 4:
                    stats["sessions"][key] = count
                else:
                    stats["agents"][key] = count
        return stats

    def reset(self, key: Optional[str] = None) -> None:
        """
        Reset rate limit windows.

        Args:
            key: Specific key to reset. If None, resets all keys.
        """
        with self._lock:
            if key is None:
                self._windows.clear()
            else:
                self._windows.pop(key, None)
