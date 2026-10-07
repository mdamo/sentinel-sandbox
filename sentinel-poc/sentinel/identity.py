"""Per-agent request authentication for the host HTTP boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from pathlib import Path


class IdentityError(ValueError):
    pass


def signature(key: bytes, agent_id: str, nonce: str, body: bytes) -> str:
    message = agent_id.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class IdentityStore:
    def __init__(self, keys: dict[str, bytes]) -> None:
        if not keys or any(len(key) < 32 for key in keys.values()):
            raise ValueError("each configured agent needs a key of at least 32 bytes")
        self._keys = dict(keys)
        self._seen: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    @classmethod
    def from_file(cls, path: str | Path) -> "IdentityStore":
        data = json.loads(Path(path).read_text())
        return cls({agent: bytes.fromhex(key) for agent, key in data.items()})

    def authenticate(self, agent_id: str, nonce: str, body: bytes,
                     supplied: str) -> str:
        key = self._keys.get(agent_id)
        if key is None or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
            raise IdentityError("invalid identity or nonce")
        expected = signature(key, agent_id, nonce, body)
        if not hmac.compare_digest(expected, supplied):
            raise IdentityError("invalid signature")
        with self._lock:
            marker = (agent_id, nonce)
            if marker in self._seen:
                raise IdentityError("replayed request")
            self._seen.add(marker)
        return agent_id


def signed_headers(agent_id: str, key: bytes, body: bytes) -> dict[str, str]:
    nonce = secrets.token_hex(16)
    return {"X-Agent-ID": agent_id, "X-Nonce": nonce,
            "X-Signature": signature(key, agent_id, nonce, body)}
