"""
AgentShield PII and secret redaction engine.

Provides regex-based redaction of sensitive data including PII (SSN, email,
phone, credit card) and secrets (API keys, JWTs, private keys, IPs).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class RedactionCategory(Enum):
    """Categories of sensitive data."""
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    API_KEY = "API_KEY"
    IP_ADDRESS = "IP_ADDRESS"
    JWT_TOKEN = "JWT_TOKEN"
    PRIVATE_KEY = "PRIVATE_KEY"
    CUSTOM = "CUSTOM"


@dataclass
class RedactionEntry:
    """Tracks a single redaction occurrence."""
    category: RedactionCategory
    original_preview: str   # first 4 chars + "***"
    placeholder: str
    count: int = 1


@dataclass
class RedactionResult:
    """Result of a redaction operation."""
    redacted_text: str
    redaction_count: int
    categories_found: List[RedactionCategory]
    entries: List[RedactionEntry]


@dataclass
class RedactionConfig:
    """Configuration for the Redactor."""
    redact_pii: bool = True
    redact_secrets: bool = True
    custom_patterns: List[Tuple[str, str]] = field(default_factory=list)
    placeholder: str = "[REDACTED]"
    use_category_labels: bool = True  # use [SSN], [EMAIL] instead of placeholder


# Built-in patterns: (category, regex_string, is_pii)
_BUILTIN_PATTERNS: List[Tuple[RedactionCategory, str, bool]] = [
    (
        RedactionCategory.SSN,
        r"\b\d{3}-\d{2}-\d{4}\b",
        True,
    ),
    (
        RedactionCategory.CREDIT_CARD,
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        True,
    ),
    (
        RedactionCategory.EMAIL,
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        True,
    ),
    (
        RedactionCategory.PHONE,
        r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        True,
    ),
    (
        RedactionCategory.API_KEY,
        r"\b(sk-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z\-_]{35})\b",
        False,
    ),
    (
        RedactionCategory.IP_ADDRESS,
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        False,
    ),
    (
        RedactionCategory.JWT_TOKEN,
        r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b",
        False,
    ),
    (
        RedactionCategory.PRIVATE_KEY,
        r"-----BEGIN\s(?:RSA\s)?PRIVATE KEY-----[\s\S]+?-----END\s(?:RSA\s)?PRIVATE KEY-----",
        False,
    ),
]


class Redactor:
    """
    Redacts PII and secrets from text using regex patterns.

    Example:
        redactor = Redactor()
        result = redactor.redact("My email is user@example.com")
        print(result.redacted_text)  # "My email is [EMAIL]"
    """

    def __init__(self, config: Optional[RedactionConfig] = None) -> None:
        self._config = config or RedactionConfig()
        # Compile: list of (category, compiled_pattern, is_pii)
        self._patterns: List[Tuple[RedactionCategory, re.Pattern, bool]] = []
        self._custom_patterns: List[Tuple[str, re.Pattern]] = []

        for cat, pattern, is_pii in _BUILTIN_PATTERNS:
            self._patterns.append((cat, re.compile(pattern, re.DOTALL), is_pii))

        for name, pattern_str in self._config.custom_patterns:
            self._custom_patterns.append((name, re.compile(pattern_str, re.DOTALL)))

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """
        Add a runtime custom redaction pattern.

        Args:
            name: Display name for this pattern.
            pattern: Regex string.
        """
        self._custom_patterns.append((name, re.compile(pattern, re.DOTALL)))

    def _label(self, category: RedactionCategory) -> str:
        """Return the replacement string for a category."""
        if self._config.use_category_labels:
            return f"[{category.value}]"
        return self._config.placeholder

    def redact(self, text: str) -> RedactionResult:
        """
        Redact sensitive data from text.

        Args:
            text: Input text to redact.

        Returns:
            RedactionResult with redacted text and metadata.
        """
        redacted = text
        total_count = 0
        categories_found: List[RedactionCategory] = []
        entries: List[RedactionEntry] = []
        entry_map: dict = {}

        for cat, compiled, is_pii in self._patterns:
            if is_pii and not self._config.redact_pii:
                continue
            if not is_pii and not self._config.redact_secrets:
                continue

            label = self._label(cat)
            matches = compiled.findall(redacted)
            # findall returns groups for patterns with groups; normalize to list of strings
            flat_matches = []
            for m in matches:
                if isinstance(m, tuple):
                    flat_matches.append(m[0] if m[0] else "")
                else:
                    flat_matches.append(m)

            count = len(flat_matches)
            if count > 0:
                redacted = compiled.sub(label, redacted)
                total_count += count
                if cat not in categories_found:
                    categories_found.append(cat)

                # Build entry
                preview_src = flat_matches[0]
                preview = (preview_src[:4] + "***") if len(preview_src) >= 4 else preview_src + "***"
                if cat in entry_map:
                    entry_map[cat].count += count
                else:
                    entry = RedactionEntry(
                        category=cat,
                        original_preview=preview,
                        placeholder=label,
                        count=count,
                    )
                    entry_map[cat] = entry
                    entries.append(entry)

        # Custom patterns
        for name, compiled in self._custom_patterns:
            matches = compiled.findall(redacted)
            flat_matches = []
            for m in matches:
                if isinstance(m, tuple):
                    flat_matches.append(m[0] if m[0] else "")
                else:
                    flat_matches.append(m)
            count = len(flat_matches)
            if count > 0:
                label = self._config.placeholder if not self._config.use_category_labels else f"[{name.upper()}]"
                redacted = compiled.sub(label, redacted)
                total_count += count
                cat = RedactionCategory.CUSTOM
                if cat not in categories_found:
                    categories_found.append(cat)
                preview_src = flat_matches[0]
                preview = (preview_src[:4] + "***") if len(preview_src) >= 4 else preview_src + "***"
                entries.append(RedactionEntry(
                    category=cat,
                    original_preview=preview,
                    placeholder=label,
                    count=count,
                ))

        return RedactionResult(
            redacted_text=redacted,
            redaction_count=total_count,
            categories_found=categories_found,
            entries=entries,
        )
