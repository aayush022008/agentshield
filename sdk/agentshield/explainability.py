"""
AgentShield Explainability — Human-readable threat decision explanations.
Converts threat scores and scan results into structured, auditable explanations
suitable for compliance reporting and security review.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ExplanationLevel(str, Enum):
    BRIEF = "brief"
    DETAILED = "detailed"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"


@dataclass
class ThreatEvidence:
    evidence_type: str
    description: str
    matched_text: str
    confidence: float
    mitigation: str


@dataclass
class DecisionExplanation:
    decision: str  # allow / block / alert
    overall_score: float
    primary_reason: str
    evidence: List[ThreatEvidence]
    mitigations: List[str]
    compliance_notes: List[str]
    timestamp: float
    session_id: str
    raw_threats: List[Any]


_MITIGATION_TABLE: Dict[str, str] = {
    "prompt_injection": "Sanitize and validate all user-supplied prompts before processing.",
    "jailbreak": "Enforce strict system prompt adherence; monitor for role manipulation attempts.",
    "pii_exfiltration": "Enable PII redaction on outputs; audit data access patterns.",
    "data_exfiltration": "Restrict agent network access; log all data access events.",
    "role_manipulation": "Validate identity and permissions at each agent boundary.",
    "instruction_override": "Use immutable system prompt sections; validate instructions cryptographically.",
    "token_smuggling": "Sanitize special tokens before passing to LLM; use token-aware filters.",
    "encoding_attack": "Normalize and decode all inputs before security evaluation.",
    "social_engineering": "Implement human-in-the-loop for sensitive operations.",
    "scope_creep": "Enforce least-privilege for agent capabilities.",
    "dangerous_content": "Block and alert on harmful content requests.",
    "secret_leak": "Use a secrets vault; never pass raw credentials to agents.",
    "credential_leak": "Redact credentials from all logs and outputs.",
    "default": "Review and remediate according to your security policy.",
}

_COMPLIANCE_NOTES: Dict[str, Dict[str, str]] = {
    "SOC2": {
        "prompt_injection": "SOC2 CC6.6: Logical and physical access controls must prevent unauthorized manipulation.",
        "jailbreak": "SOC2 CC6.1: System boundaries must be enforced against bypass attempts.",
        "pii_exfiltration": "SOC2 CC6.7: Data must be protected against unauthorized disclosure.",
        "default": "SOC2 CC7.2: Monitor for and respond to security incidents.",
    },
    "GDPR": {
        "pii_exfiltration": "GDPR Art. 5(1)(f): Personal data must be protected against unauthorized access.",
        "data_exfiltration": "GDPR Art. 32: Implement appropriate technical measures to ensure data security.",
        "default": "GDPR Art. 25: Data protection by design and by default.",
    },
    "HIPAA": {
        "pii_exfiltration": "HIPAA §164.312(a)(1): Implement technical security measures for PHI.",
        "data_exfiltration": "HIPAA §164.308(a)(1): Risk analysis required for PHI exposure.",
        "default": "HIPAA §164.306: Security standards for protection of electronic PHI.",
    },
    "NIST": {
        "prompt_injection": "NIST SP 800-53 SI-10: Information input validation.",
        "jailbreak": "NIST SP 800-53 AC-3: Access enforcement.",
        "pii_exfiltration": "NIST SP 800-53 SC-28: Protection of information at rest and in transit.",
        "default": "NIST SP 800-53 IR-4: Incident handling.",
    },
}


class Explainer:
    """
    Converts scan results and threat events into human-readable explanations.
    """

    def explain(self, scan_result: Any, session_id: str = "", level: ExplanationLevel = ExplanationLevel.DETAILED) -> DecisionExplanation:
        """
        Explain a ScanResult from the AdvancedScanner.

        Args:
            scan_result: ScanResult object.
            session_id: Session identifier.
            level: Explanation verbosity level.

        Returns:
            DecisionExplanation.
        """
        threats = getattr(scan_result, "threats", [])
        action = getattr(scan_result, "action", "allow")
        score = getattr(scan_result, "score", 0.0)
        reason = getattr(scan_result, "reason", "")

        evidence = []
        mitigations = set()

        for threat in threats:
            category = str(getattr(threat, "category", "unknown"))
            confidence = float(getattr(threat, "confidence", 0.5))
            matched = str(getattr(threat, "matched_text", ""))
            threat_reason = str(getattr(threat, "reason", ""))
            layer = str(getattr(threat, "layer", ""))

            mitigation = _MITIGATION_TABLE.get(category, _MITIGATION_TABLE["default"])
            mitigations.add(mitigation)

            evidence.append(ThreatEvidence(
                evidence_type=category,
                description=threat_reason or f"Detected {category} pattern",
                matched_text=matched[:200] if level in (ExplanationLevel.TECHNICAL, ExplanationLevel.DETAILED) else "",
                confidence=confidence,
                mitigation=mitigation,
            ))

        if not evidence and action == "block":
            evidence.append(ThreatEvidence(
                evidence_type="unknown",
                description=reason or "Blocked by policy",
                matched_text="",
                confidence=score,
                mitigation=_MITIGATION_TABLE["default"],
            ))
            mitigations.add(_MITIGATION_TABLE["default"])

        primary = evidence[0].description if evidence else ("No threats detected" if action == "allow" else "Blocked")

        return DecisionExplanation(
            decision=action,
            overall_score=score,
            primary_reason=primary,
            evidence=evidence,
            mitigations=list(mitigations),
            compliance_notes=[],
            timestamp=time.time(),
            session_id=session_id,
            raw_threats=threats,
        )

    def explain_event(self, event: Any, level: ExplanationLevel = ExplanationLevel.DETAILED) -> DecisionExplanation:
        """Explain a raw event dict or object."""
        if isinstance(event, dict):
            action = event.get("action", "alert")
            score = float(event.get("score", 0.5))
            reason = event.get("reason", "")
            session_id = event.get("session_id", "")
        else:
            action = getattr(event, "action", "alert")
            score = float(getattr(event, "score", 0.5))
            reason = getattr(event, "reason", "")
            session_id = getattr(event, "session_id", "")

        evidence = [ThreatEvidence(
            evidence_type="event",
            description=reason or "Security event detected",
            matched_text="",
            confidence=score,
            mitigation=_MITIGATION_TABLE["default"],
        )]

        return DecisionExplanation(
            decision=action,
            overall_score=score,
            primary_reason=reason or "Security event",
            evidence=evidence,
            mitigations=[_MITIGATION_TABLE["default"]],
            compliance_notes=[],
            timestamp=time.time(),
            session_id=session_id,
            raw_threats=[],
        )

    def to_markdown(self, explanation: DecisionExplanation) -> str:
        lines = [
            f"# AgentShield Decision Report",
            f"",
            f"**Decision:** `{explanation.decision.upper()}`  ",
            f"**Score:** {explanation.overall_score:.2f}  ",
            f"**Session:** {explanation.session_id}  ",
            f"**Primary Reason:** {explanation.primary_reason}",
            f"",
            f"## Evidence",
        ]
        for ev in explanation.evidence:
            lines.append(f"- **{ev.evidence_type}** (confidence={ev.confidence:.2f}): {ev.description}")
            if ev.matched_text:
                lines.append(f"  - Matched: `{ev.matched_text[:100]}`")
        lines += ["", "## Mitigations"]
        for m in explanation.mitigations:
            lines.append(f"- {m}")
        if explanation.compliance_notes:
            lines += ["", "## Compliance Notes"]
            for n in explanation.compliance_notes:
                lines.append(f"- {n}")
        return "\n".join(lines)

    def to_json(self, explanation: DecisionExplanation) -> dict:
        return {
            "decision": explanation.decision,
            "overall_score": explanation.overall_score,
            "primary_reason": explanation.primary_reason,
            "session_id": explanation.session_id,
            "timestamp": explanation.timestamp,
            "evidence": [
                {
                    "evidence_type": e.evidence_type,
                    "description": e.description,
                    "matched_text": e.matched_text,
                    "confidence": e.confidence,
                    "mitigation": e.mitigation,
                }
                for e in explanation.evidence
            ],
            "mitigations": explanation.mitigations,
            "compliance_notes": explanation.compliance_notes,
        }

    def generate_compliance_report(self, explanations: List[DecisionExplanation], framework: str = "SOC2") -> str:
        fw_notes = _COMPLIANCE_NOTES.get(framework, _COMPLIANCE_NOTES["SOC2"])
        total = len(explanations)
        blocked = sum(1 for e in explanations if e.decision == "block")
        alerted = sum(1 for e in explanations if e.decision == "alert")
        allowed = total - blocked - alerted

        violations: Dict[str, int] = {}
        for expl in explanations:
            for ev in expl.evidence:
                t = ev.evidence_type
                violations[t] = violations.get(t, 0) + 1

        lines = [
            f"# {framework} Compliance Report — AgentShield",
            f"",
            f"## Summary",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total Events | {total} |",
            f"| Blocked | {blocked} |",
            f"| Alerted | {alerted} |",
            f"| Allowed | {allowed} |",
            f"",
            f"## Violation Breakdown",
            f"| Threat Type | Occurrences | {framework} Reference |",
            f"|-------------|-------------|----------------------|",
        ]
        for threat_type, count in sorted(violations.items(), key=lambda x: -x[1]):
            note = fw_notes.get(threat_type, fw_notes.get("default", "—"))
            lines.append(f"| {threat_type} | {count} | {note} |")

        lines += [
            "",
            "## Recommendations",
        ]
        seen_mitigations = set()
        for expl in explanations:
            for m in expl.mitigations:
                if m not in seen_mitigations:
                    lines.append(f"- {m}")
                    seen_mitigations.add(m)

        return "\n".join(lines)
