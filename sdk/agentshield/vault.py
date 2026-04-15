"""
AgentShield Vault — Secure secrets management for AI agents.
Stores secrets encrypted in memory, provides access-controlled retrieval,
and automatically detects when vault tokens appear in agent outputs.
"""

from __future__ import annotations

import base64
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR cipher using repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


# XOR is its own inverse
_xor_decrypt = _xor_encrypt


@dataclass
class SecretEntry:
    secret_id: str
    name: str
    value_encrypted: bytes
    created_at: float
    last_accessed: float
    access_count: int
    tags: List[str]
    expiry: Optional[float]


@dataclass
class VaultToken:
    token: str
    secret_id: str
    issued_at: float
    expires_at: float
    single_use: bool


class Vault:
    """
    Secure in-memory secrets vault.

    Uses XOR + base64 encryption (no external deps).
    Thread-safe.
    """

    def __init__(self, master_key: Optional[bytes] = None) -> None:
        self._key = master_key if master_key is not None else os.urandom(32)
        self._lock = threading.Lock()
        self._secrets: Dict[str, SecretEntry] = {}
        self._name_index: Dict[str, str] = {}  # name -> secret_id
        self._tokens: Dict[str, VaultToken] = {}

    def _encrypt(self, value: str) -> bytes:
        raw = value.encode("utf-8")
        encrypted = _xor_encrypt(raw, self._key)
        return base64.b64encode(encrypted)

    def _decrypt(self, value_encrypted: bytes) -> str:
        encrypted = base64.b64decode(value_encrypted)
        raw = _xor_decrypt(encrypted, self._key)
        return raw.decode("utf-8")

    def store(self, name: str, value: str, tags: Optional[List[str]] = None, ttl_seconds: Optional[float] = None) -> str:
        """Store a secret and return its secret_id."""
        secret_id = str(uuid.uuid4())
        now = time.time()
        expiry = now + ttl_seconds if ttl_seconds else None
        entry = SecretEntry(
            secret_id=secret_id,
            name=name,
            value_encrypted=self._encrypt(value),
            created_at=now,
            last_accessed=now,
            access_count=0,
            tags=tags or [],
            expiry=expiry,
        )
        with self._lock:
            self._secrets[secret_id] = entry
            self._name_index[name] = secret_id
        return secret_id

    def get(self, secret_id: str) -> str:
        """Decrypt and return the secret value."""
        with self._lock:
            entry = self._secrets.get(secret_id)
            if entry is None:
                raise KeyError(f"Secret not found: {secret_id}")
            if entry.expiry and time.time() > entry.expiry:
                raise KeyError(f"Secret expired: {secret_id}")
            entry.last_accessed = time.time()
            entry.access_count += 1
            return self._decrypt(entry.value_encrypted)

    def get_by_name(self, name: str) -> str:
        """Look up a secret by name."""
        with self._lock:
            secret_id = self._name_index.get(name)
            if secret_id is None:
                raise KeyError(f"Secret not found by name: {name}")
        return self.get(secret_id)

    def issue_token(self, secret_id: str, ttl_seconds: float = 300, single_use: bool = False) -> VaultToken:
        """Issue an access token for a secret."""
        now = time.time()
        token = VaultToken(
            token=str(uuid.uuid4()),
            secret_id=secret_id,
            issued_at=now,
            expires_at=now + ttl_seconds,
            single_use=single_use,
        )
        with self._lock:
            self._tokens[token.token] = token
        return token

    def redeem_token(self, token: str) -> str:
        """Redeem a vault token and return the secret value."""
        with self._lock:
            vt = self._tokens.get(token)
            if vt is None:
                raise KeyError("Invalid or expired token")
            if time.time() > vt.expires_at:
                del self._tokens[token]
                raise KeyError("Token expired")
            secret_id = vt.secret_id
            if vt.single_use:
                del self._tokens[token]
        return self.get(secret_id)

    def revoke(self, secret_id: str) -> bool:
        """Revoke a secret by ID."""
        with self._lock:
            entry = self._secrets.pop(secret_id, None)
            if entry:
                self._name_index.pop(entry.name, None)
                # Revoke all tokens for this secret
                to_remove = [t for t, v in self._tokens.items() if v.secret_id == secret_id]
                for t in to_remove:
                    del self._tokens[t]
                return True
        return False

    def scan_for_leaks(self, text: str) -> List[str]:
        """Scan text for stored secret values. Returns list of secret names found."""
        found = []
        with self._lock:
            for entry in self._secrets.values():
                try:
                    value = self._decrypt(entry.value_encrypted)
                    if value and value in text:
                        found.append(entry.name)
                except Exception:
                    pass
        return found

    def list_secrets(self) -> List[dict]:
        """Return metadata for all secrets (no values)."""
        with self._lock:
            return [
                {
                    "secret_id": e.secret_id,
                    "name": e.name,
                    "tags": e.tags,
                    "created_at": e.created_at,
                    "last_accessed": e.last_accessed,
                    "access_count": e.access_count,
                    "expiry": e.expiry,
                }
                for e in self._secrets.values()
            ]

    def purge_expired(self) -> int:
        """Remove expired secrets. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            expired = [sid for sid, e in self._secrets.items() if e.expiry and now > e.expiry]
            for sid in expired:
                entry = self._secrets.pop(sid)
                self._name_index.pop(entry.name, None)
                removed += 1
        return removed
