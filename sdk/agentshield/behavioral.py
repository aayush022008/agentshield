"""
AgentShield Behavioral — Session behavioral fingerprinting.
Builds baseline behavioral profiles and detects anomalous deviations that may indicate
session hijacking, account takeover, or agent compromise.
"""

from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class BehaviorSignal(str, Enum):
    TYPING_SPEED = "typing_speed"
    TOOL_PREFERENCE = "tool_preference"
    REQUEST_TIMING = "request_timing"
    VOCABULARY_STYLE = "vocabulary_style"
    TOPIC_DISTRIBUTION = "topic_distribution"
    ERROR_RATE = "error_rate"


@dataclass
class BehavioralFingerprint:
    session_id: str
    tool_usage_freq: Dict[str, int]
    avg_prompt_length: float
    vocab_set: Set[str]
    request_interval_avg: float
    error_rate: float
    topic_vector: Dict[str, int]
    sample_count: int
    created_at: float
    last_updated: float
    # Baseline snapshot
    _baseline: Optional["BehavioralFingerprint"] = field(default=None, repr=False, compare=False)
    _length_samples: List[float] = field(default_factory=list, repr=False, compare=False)
    _last_timestamp: Optional[float] = field(default=None, repr=False, compare=False)
    _interval_samples: List[float] = field(default_factory=list, repr=False, compare=False)
    _error_count: int = field(default=0, repr=False, compare=False)


@dataclass
class DeviationResult:
    is_deviation: bool
    deviation_score: float
    signals_triggered: List[BehaviorSignal]
    reason: str


def _tokenize(text: str) -> List[str]:
    return [w.lower() for w in re.findall(r"\b[a-zA-Z]{3,}\b", text)]


class BehavioralAnalyzer:
    """
    Session behavioral fingerprinting engine.
    Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._profiles: Dict[str, BehavioralFingerprint] = {}

    def _get_or_create(self, session_id: str) -> BehavioralFingerprint:
        if session_id not in self._profiles:
            now = time.time()
            self._profiles[session_id] = BehavioralFingerprint(
                session_id=session_id,
                tool_usage_freq={},
                avg_prompt_length=0.0,
                vocab_set=set(),
                request_interval_avg=0.0,
                error_rate=0.0,
                topic_vector={},
                sample_count=0,
                created_at=now,
                last_updated=now,
            )
        return self._profiles[session_id]

    def update_profile(
        self,
        session_id: str,
        prompt: str,
        tool_name: Optional[str] = None,
        is_error: bool = False,
        timestamp: Optional[float] = None,
    ) -> None:
        """Update the behavioral fingerprint for a session."""
        ts = timestamp or time.time()
        with self._lock:
            fp = self._get_or_create(session_id)

            # Update interval
            if fp._last_timestamp is not None:
                interval = ts - fp._last_timestamp
                fp._interval_samples.append(interval)
                fp.request_interval_avg = sum(fp._interval_samples) / len(fp._interval_samples)
            fp._last_timestamp = ts

            # Update length
            length = len(prompt)
            fp._length_samples.append(float(length))
            fp.avg_prompt_length = sum(fp._length_samples) / len(fp._length_samples)

            # Update vocab (top 50)
            tokens = _tokenize(prompt)
            fp.vocab_set.update(tokens)
            if len(fp.vocab_set) > 50:
                fp.vocab_set = set(list(fp.vocab_set)[:50])

            # Update topic vector
            for word in tokens:
                fp.topic_vector[word] = fp.topic_vector.get(word, 0) + 1

            # Tool usage
            if tool_name:
                fp.tool_usage_freq[tool_name] = fp.tool_usage_freq.get(tool_name, 0) + 1

            # Error rate
            if is_error:
                fp._error_count += 1
            fp.sample_count += 1
            fp.error_rate = fp._error_count / fp.sample_count
            fp.last_updated = ts

    def compare(self, session_id: str, prompt: str, tool_name: Optional[str] = None) -> DeviationResult:
        """Compare current input against baseline fingerprint."""
        with self._lock:
            fp = self._profiles.get(session_id)

        if fp is None or fp._baseline is None:
            return DeviationResult(False, 0.0, [], "No baseline established")

        baseline = fp._baseline
        signals: List[BehaviorSignal] = []
        score = 0.0
        reasons = []

        # 1. Prompt length deviation
        if len(baseline._length_samples) >= 2:
            mean = baseline.avg_prompt_length
            variance = sum((x - mean) ** 2 for x in baseline._length_samples) / len(baseline._length_samples)
            std = math.sqrt(variance) if variance > 0 else 1.0
            z = abs(len(prompt) - mean) / std
            if z > 2.0:
                signals.append(BehaviorSignal.TYPING_SPEED)
                score += min(0.3, z / 10)
                reasons.append(f"Prompt length z-score={z:.1f}")

        # 2. Vocabulary overlap
        current_tokens = set(_tokenize(prompt))
        if baseline.vocab_set:
            overlap = len(current_tokens & baseline.vocab_set) / max(len(current_tokens), 1)
            if overlap < 0.10:
                signals.append(BehaviorSignal.VOCABULARY_STYLE)
                score += 0.35
                reasons.append(f"Low vocab overlap={overlap:.2f}")

        # 3. Tool preference shift
        if tool_name and baseline.tool_usage_freq and tool_name not in baseline.tool_usage_freq:
            signals.append(BehaviorSignal.TOOL_PREFERENCE)
            score += 0.2
            reasons.append(f"New tool: {tool_name}")

        # 4. Request timing anomaly
        if fp._last_timestamp is not None and baseline.request_interval_avg > 0:
            pass  # timing only meaningful after update; skip here

        score = min(1.0, score)
        is_dev = len(signals) > 0

        return DeviationResult(
            is_deviation=is_dev,
            deviation_score=score,
            signals_triggered=signals,
            reason="; ".join(reasons) if reasons else "Normal",
        )

    def get_fingerprint(self, session_id: str) -> Optional[BehavioralFingerprint]:
        with self._lock:
            return self._profiles.get(session_id)

    def establish_baseline(self, session_id: str) -> bool:
        """Mark current profile as baseline. Requires >= 5 samples."""
        import copy
        with self._lock:
            fp = self._profiles.get(session_id)
            if fp is None or fp.sample_count < 5:
                return False
            fp._baseline = copy.deepcopy(fp)
            fp._baseline._baseline = None
        return True

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._profiles.pop(session_id, None)
