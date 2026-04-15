"""
AgentShield metrics collector.

Pure-Python singleton metrics module with counter, gauge, and histogram support.
Exports in Prometheus text format and JSON.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class Metric:
    """Represents a single metric."""
    name: str
    type: MetricType
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    help_text: str = ""
    buckets: List[float] = field(default_factory=list)
    # Histogram internals
    sum: float = 0.0
    count: int = 0
    # bucket_counts[i] = count of observations <= buckets[i]
    bucket_counts: List[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.type == MetricType.HISTOGRAM and self.buckets:
            if not self.bucket_counts:
                self.bucket_counts = [0] * len(self.buckets)


_PRE_DEFINED: List[tuple] = [
    ("agentshield_threats_detected_total", MetricType.COUNTER, "Total threats detected", []),
    ("agentshield_events_processed_total", MetricType.COUNTER, "Total events processed", []),
    ("agentshield_blocks_total", MetricType.COUNTER, "Total blocked requests", []),
    ("agentshield_alerts_total", MetricType.COUNTER, "Total alerts generated", []),
    ("agentshield_active_sessions", MetricType.GAUGE, "Currently active sessions", []),
    ("agentshield_llm_latency_ms", MetricType.HISTOGRAM, "LLM call latency in ms", [10, 50, 100, 500, 1000, 5000]),
    ("agentshield_tool_latency_ms", MetricType.HISTOGRAM, "Tool call latency in ms", [1, 10, 50, 100, 500]),
    ("agentshield_scan_duration_ms", MetricType.HISTOGRAM, "Scan duration in ms", [0.1, 1, 5, 10, 50]),
    ("agentshield_threat_score", MetricType.GAUGE, "Current threat score", []),
]


class MetricsCollector:
    """
    Singleton metrics collector supporting counters, gauges, and histograms.

    Usage:
        mc = MetricsCollector.get_instance()
        mc.increment("agentshield_threats_detected_total")
        mc.set_gauge("agentshield_active_sessions", 3)
        mc.observe("agentshield_llm_latency_ms", 145.2)
    """

    _instance: Optional["MetricsCollector"] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metrics: Dict[str, Metric] = {}
        self._init_predefined()

    @classmethod
    def get_instance(cls) -> "MetricsCollector":
        """Return the singleton MetricsCollector instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _init_predefined(self) -> None:
        """Initialize all pre-defined metrics."""
        for name, mtype, help_text, buckets in _PRE_DEFINED:
            m = Metric(name=name, type=mtype, help_text=help_text, buckets=buckets)
            if mtype == MetricType.HISTOGRAM and buckets:
                m.bucket_counts = [0] * len(buckets)
            self._metrics[name] = m

    def increment(self, name: str, value: float = 1, labels: Optional[Dict] = None) -> None:
        """
        Increment a counter metric.

        Args:
            name: Metric name.
            value: Amount to increment by (default 1).
            labels: Optional label dict (stored on metric).
        """
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Metric(name=name, type=MetricType.COUNTER)
            m = self._metrics[name]
            m.value += value
            if labels:
                m.labels.update(labels)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict] = None) -> None:
        """
        Set a gauge metric to an absolute value.

        Args:
            name: Metric name.
            value: New value.
            labels: Optional label dict.
        """
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Metric(name=name, type=MetricType.GAUGE)
            m = self._metrics[name]
            m.value = value
            if labels:
                m.labels.update(labels)

    def observe(self, name: str, value: float, labels: Optional[Dict] = None) -> None:
        """
        Record a histogram observation.

        Args:
            name: Metric name.
            value: Observed value.
            labels: Optional label dict.
        """
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Metric(name=name, type=MetricType.HISTOGRAM)
            m = self._metrics[name]
            m.sum += value
            m.count += 1
            if labels:
                m.labels.update(labels)
            for i, bucket in enumerate(m.buckets):
                if value <= bucket:
                    m.bucket_counts[i] += 1

    def record_event(self, event: Any) -> None:
        """
        Auto-record metrics from an InterceptorEvent.

        Args:
            event: InterceptorEvent with type, threat_score, latency_ms attributes.
        """
        self.increment("agentshield_events_processed_total")

        threat_score = getattr(event, "threat_score", None)
        if threat_score is not None:
            self.set_gauge("agentshield_threat_score", float(threat_score))
            if threat_score > 0:
                self.increment("agentshield_threats_detected_total")

        event_type = str(getattr(event, "type", ""))
        latency = getattr(event, "latency_ms", None)
        if latency is not None:
            if "llm" in event_type.lower() or "prompt" in event_type.lower():
                self.observe("agentshield_llm_latency_ms", float(latency))
            elif "tool" in event_type.lower():
                self.observe("agentshield_tool_latency_ms", float(latency))

        blocked = getattr(event, "blocked", False)
        if blocked:
            self.increment("agentshield_blocks_total")

    def export_prometheus(self) -> str:
        """
        Export metrics in Prometheus text format.

        Returns:
            Multi-line string in Prometheus exposition format.
        """
        lines: List[str] = []
        with self._lock:
            for name, m in self._metrics.items():
                if m.help_text:
                    lines.append(f"# HELP {name} {m.help_text}")
                lines.append(f"# TYPE {name} {m.type.value}")

                if m.type == MetricType.HISTOGRAM:
                    for i, bucket in enumerate(m.buckets):
                        bc = m.bucket_counts[i] if i < len(m.bucket_counts) else 0
                        lines.append(f'{name}_bucket{{le="{bucket}"}} {bc}')
                    lines.append(f'{name}_bucket{{le="+Inf"}} {m.count}')
                    lines.append(f"{name}_sum {m.sum}")
                    lines.append(f"{name}_count {m.count}")
                else:
                    label_str = ""
                    if m.labels:
                        parts = [f'{k}="{v}"' for k, v in m.labels.items()]
                        label_str = "{" + ",".join(parts) + "}"
                    lines.append(f"{name}{label_str} {m.value}")

        return "\n".join(lines)

    def export_json(self) -> dict:
        """
        Export metrics as a JSON-serializable dict.

        Returns:
            Dict mapping metric names to their data.
        """
        result: dict = {}
        with self._lock:
            for name, m in self._metrics.items():
                entry: dict = {
                    "type": m.type.value,
                    "help": m.help_text,
                    "labels": dict(m.labels),
                }
                if m.type == MetricType.HISTOGRAM:
                    entry["sum"] = m.sum
                    entry["count"] = m.count
                    entry["buckets"] = {
                        str(b): (m.bucket_counts[i] if i < len(m.bucket_counts) else 0)
                        for i, b in enumerate(m.buckets)
                    }
                else:
                    entry["value"] = m.value
                result[name] = entry
        return result

    def reset(self) -> None:
        """Reset all metric values (useful for testing)."""
        with self._lock:
            self._metrics.clear()
            self._init_predefined()
