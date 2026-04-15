"""
AgentShield real-time threat feed.

Provides a publish/subscribe system for threat alerts with thread-safe
background dispatch and deque-based history.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional


class AlertSeverity(Enum):
    """Severity levels for threat alerts."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ThreatAlert:
    """Represents a threat alert event."""
    alert_id: str
    session_id: str
    severity: AlertSeverity
    category: str
    message: str
    timestamp: float
    event_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        session_id: str,
        severity: AlertSeverity,
        category: str,
        message: str,
        event_data: Optional[Dict[str, Any]] = None,
    ) -> "ThreatAlert":
        """Create a new ThreatAlert with auto-generated ID and timestamp."""
        return cls(
            alert_id=str(uuid.uuid4()),
            session_id=session_id,
            severity=severity,
            category=category,
            message=message,
            timestamp=time.time(),
            event_data=event_data or {},
        )


class RealTimeFeed:
    """
    Thread-safe real-time threat alert feed.

    Supports multiple subscribers receiving alerts via callbacks dispatched
    in background threads. Maintains a rolling history of the last 1000 alerts.
    """

    _MAX_HISTORY = 1000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: Dict[str, Callable[[ThreatAlert], None]] = {}
        self._history: Deque[ThreatAlert] = deque(maxlen=self._MAX_HISTORY)
        self._total_published = 0
        self._severity_counts: Dict[str, int] = {s.value: 0 for s in AlertSeverity}

    def subscribe(self, callback: Callable[[ThreatAlert], None]) -> str:
        """
        Register a callback to receive threat alerts.

        Args:
            callback: Function called with each ThreatAlert.

        Returns:
            subscription_id: Use this to unsubscribe later.
        """
        sub_id = str(uuid.uuid4())
        with self._lock:
            self._subscribers[sub_id] = callback
        return sub_id

    def unsubscribe(self, subscription_id: str) -> bool:
        """
        Remove a subscriber.

        Args:
            subscription_id: ID returned from subscribe().

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if subscription_id in self._subscribers:
                del self._subscribers[subscription_id]
                return True
        return False

    def publish(self, alert: ThreatAlert) -> None:
        """
        Publish a threat alert to all subscribers.

        Each subscriber callback is invoked in a separate background thread.
        The alert is added to the rolling history.

        Args:
            alert: The ThreatAlert to publish.
        """
        with self._lock:
            self._history.append(alert)
            self._total_published += 1
            self._severity_counts[alert.severity.value] = (
                self._severity_counts.get(alert.severity.value, 0) + 1
            )
            callbacks = list(self._subscribers.values())

        for cb in callbacks:
            t = threading.Thread(target=self._safe_dispatch, args=(cb, alert), daemon=True)
            t.start()

    def _safe_dispatch(self, callback: Callable[[ThreatAlert], None], alert: ThreatAlert) -> None:
        """Dispatch an alert to a callback, swallowing exceptions."""
        try:
            callback(alert)
        except Exception:
            pass

    def get_recent_alerts(self, limit: int = 50) -> List[ThreatAlert]:
        """
        Return the most recent alerts.

        Args:
            limit: Maximum number of alerts to return (newest last).

        Returns:
            List of ThreatAlert objects.
        """
        with self._lock:
            alerts = list(self._history)
        return alerts[-limit:]

    def get_stats(self) -> dict:
        """
        Return feed statistics.

        Returns:
            Dict with severity counts, total_published, and active_subscribers.
        """
        with self._lock:
            return {
                "severity_counts": dict(self._severity_counts),
                "total_published": self._total_published,
                "active_subscribers": len(self._subscribers),
            }

    def create_alert_from_event(self, event: Any, severity: AlertSeverity) -> ThreatAlert:
        """
        Factory method: create a ThreatAlert from an InterceptorEvent.

        Args:
            event: An InterceptorEvent (or any object with session_id, type, data attributes).
            severity: AlertSeverity level.

        Returns:
            A new ThreatAlert.
        """
        session_id = getattr(event, "session_id", "")
        category = str(getattr(event, "type", "unknown"))
        message = f"Threat detected: {category}"
        event_data = getattr(event, "data", {}) or {}
        return ThreatAlert.create(
            session_id=session_id,
            severity=severity,
            category=category,
            message=message,
            event_data=event_data if isinstance(event_data, dict) else {},
        )
