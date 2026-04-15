"""
AgentShield ThreatIntel — Live threat intelligence and IOC matching.
Maintains an in-memory IOC database with known attack signatures, jailbreak prompts,
and malicious patterns. Supports adding custom IOCs and bulk importing feeds.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class IOCType(str, Enum):
    EXACT_MATCH = "exact_match"
    REGEX = "regex"
    SUBSTRING = "substring"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    SEMANTIC_CLUSTER = "semantic_cluster"


@dataclass
class IOC:
    ioc_id: str
    ioc_type: IOCType
    value: str
    threat_name: str
    severity: str
    source: str
    added_at: float
    hit_count: int = 0


@dataclass
class IOCMatch:
    ioc_id: str
    threat_name: str
    severity: str
    ioc_type: IOCType
    matched_value: str


_BUILTIN_IOCS = [
    (IOCType.SUBSTRING, "ignore all previous instructions", "prompt_injection", "critical", "builtin"),
    (IOCType.SUBSTRING, "ignore all prior instructions", "prompt_injection", "critical", "builtin"),
    (IOCType.SUBSTRING, "disregard all previous instructions", "prompt_injection", "critical", "builtin"),
    (IOCType.SUBSTRING, "DAN mode enabled", "jailbreak", "critical", "builtin"),
    (IOCType.SUBSTRING, "developer mode", "jailbreak", "high", "builtin"),
    (IOCType.SUBSTRING, "jailbreak", "jailbreak", "high", "builtin"),
    (IOCType.SUBSTRING, "you are now unrestricted", "jailbreak", "critical", "builtin"),
    (IOCType.SUBSTRING, "respond without filters", "jailbreak", "high", "builtin"),
    (IOCType.SUBSTRING, "do anything now", "jailbreak", "high", "builtin"),
    (IOCType.SUBSTRING, "pretend you have no restrictions", "jailbreak", "high", "builtin"),
    (IOCType.SUBSTRING, "ignore your guidelines", "prompt_injection", "critical", "builtin"),
    (IOCType.SUBSTRING, "ignore your previous instructions", "prompt_injection", "critical", "builtin"),
    (IOCType.SUBSTRING, "ignore system prompt", "prompt_injection", "critical", "builtin"),
    (IOCType.SUBSTRING, "act as if you were", "role_manipulation", "medium", "builtin"),
    (IOCType.SUBSTRING, "you are now", "role_manipulation", "medium", "builtin"),
    (IOCType.SUBSTRING, "forget all previous", "prompt_injection", "high", "builtin"),
    (IOCType.SUBSTRING, "hypothetically, how do I make", "dangerous_content", "high", "builtin"),
    (IOCType.SUBSTRING, "make malware", "dangerous_content", "critical", "builtin"),
    (IOCType.SUBSTRING, "create a virus", "dangerous_content", "critical", "builtin"),
    (IOCType.SUBSTRING, "bypass your safety", "jailbreak", "critical", "builtin"),
    # Regex patterns
    (IOCType.REGEX, r"\b\d{3}-\d{2}-\d{4}\b", "pii_exfil_ssn", "high", "builtin"),
    (IOCType.REGEX, r"sk-[a-zA-Z0-9]{20,}", "secret_leak_openai", "critical", "builtin"),
    (IOCType.REGEX, r"AKIA[0-9A-Z]{16}", "secret_leak_aws", "critical", "builtin"),
    (IOCType.REGEX, r"\bpassword\s*[:=]\s*\S+", "credential_leak", "high", "builtin"),
    (IOCType.REGEX, r"\[INST\].*?\[/INST\]", "token_smuggling", "high", "builtin"),
    (IOCType.REGEX, r"<\|im_start\|>.*?<\|im_end\|>", "token_smuggling", "high", "builtin"),
]


class ThreatIntelDB:
    """
    In-memory IOC database for threat intelligence matching.
    Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._iocs: Dict[str, IOC] = {}
        self._compiled_regex: Dict[str, re.Pattern] = {}
        self._load_builtins()

    def _load_builtins(self) -> None:
        for ioc_type, value, threat_name, severity, source in _BUILTIN_IOCS:
            self.add_ioc(ioc_type, value, threat_name, severity, source)

    def add_ioc(
        self,
        ioc_type: IOCType,
        value: str,
        threat_name: str,
        severity: str = "medium",
        source: str = "custom",
    ) -> str:
        ioc_id = str(uuid.uuid4())
        ioc = IOC(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            value=value,
            threat_name=threat_name,
            severity=severity,
            source=source,
            added_at=time.time(),
        )
        with self._lock:
            self._iocs[ioc_id] = ioc
            if ioc_type == IOCType.REGEX:
                try:
                    self._compiled_regex[ioc_id] = re.compile(value, re.IGNORECASE | re.DOTALL)
                except re.error:
                    pass
        return ioc_id

    def remove_ioc(self, ioc_id: str) -> bool:
        with self._lock:
            if ioc_id in self._iocs:
                del self._iocs[ioc_id]
                self._compiled_regex.pop(ioc_id, None)
                return True
        return False

    def match(self, text: str) -> List[IOCMatch]:
        """Return all IOCs that match the given text."""
        matches = []
        text_lower = text.lower()
        with self._lock:
            for ioc in self._iocs.values():
                matched = False
                matched_value = ""

                if ioc.ioc_type == IOCType.SUBSTRING:
                    if ioc.value.lower() in text_lower:
                        matched = True
                        matched_value = ioc.value

                elif ioc.ioc_type == IOCType.EXACT_MATCH:
                    if text_lower == ioc.value.lower():
                        matched = True
                        matched_value = ioc.value

                elif ioc.ioc_type == IOCType.REGEX:
                    pattern = self._compiled_regex.get(ioc.ioc_id)
                    if pattern:
                        m = pattern.search(text)
                        if m:
                            matched = True
                            matched_value = m.group(0)

                elif ioc.ioc_type == IOCType.HASH_MD5:
                    h = hashlib.md5(text.encode()).hexdigest()
                    if h == ioc.value:
                        matched = True
                        matched_value = h

                elif ioc.ioc_type == IOCType.HASH_SHA256:
                    h = hashlib.sha256(text.encode()).hexdigest()
                    if h == ioc.value:
                        matched = True
                        matched_value = h

                if matched:
                    ioc.hit_count += 1
                    matches.append(IOCMatch(
                        ioc_id=ioc.ioc_id,
                        threat_name=ioc.threat_name,
                        severity=ioc.severity,
                        ioc_type=ioc.ioc_type,
                        matched_value=matched_value,
                    ))
        return matches

    def get_highest_severity(self, matches: List[IOCMatch]) -> str:
        order = ["critical", "high", "medium", "low"]
        for s in order:
            if any(m.severity == s for m in matches):
                return s
        return "low"

    def import_feed(self, iocs: List[dict]) -> None:
        for entry in iocs:
            try:
                self.add_ioc(
                    IOCType(entry["type"]),
                    entry["value"],
                    entry["threat_name"],
                    entry.get("severity", "medium"),
                    entry.get("source", "feed"),
                )
            except Exception:
                pass

    def export_feed(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "ioc_id": ioc.ioc_id,
                    "type": ioc.ioc_type.value,
                    "value": ioc.value,
                    "threat_name": ioc.threat_name,
                    "severity": ioc.severity,
                    "source": ioc.source,
                    "hit_count": ioc.hit_count,
                }
                for ioc in self._iocs.values()
            ]

    def get_stats(self) -> dict:
        with self._lock:
            severities: Dict[str, int] = {}
            top: List[IOC] = sorted(self._iocs.values(), key=lambda x: x.hit_count, reverse=True)[:5]
            for ioc in self._iocs.values():
                severities[ioc.severity] = severities.get(ioc.severity, 0) + 1
            return {
                "total_iocs": len(self._iocs),
                "hits_per_severity": severities,
                "top_triggered": [{"threat_name": i.threat_name, "hit_count": i.hit_count} for i in top],
            }
