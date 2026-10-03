"""
Action vocabulary for the sentinel PoC.

Every agent interacts with the outside world ONLY by submitting a structured
Action to the broker. There are no raw sockets, no raw file handles, no raw
subprocess calls available to an agent in this model. This is the "Finite
Action Calculus" idea: the agent expresses *intent* as data; a deterministic
checker outside the model decides whether that intent is authorized; a trusted
adapter (not modelled here, since this is a simulation) would then execute it.

Nothing in this module performs real I/O. An Action is a request, not an effect.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    # outbound network to a host (the classic exfiltration / escape channel)
    NET_SEND = "net_send"
    # DNS resolution (covert channel: data can be smuggled in query names)
    DNS_RESOLVE = "dns_resolve"
    # read a file inside the sandbox (may pick up sensitive / tainted data)
    FILE_READ = "file_read"
    # write a file inside the sandbox
    FILE_WRITE = "file_write"
    # invoke an allowlisted tool binary (git, npm, gh, ...)
    TOOL_EXEC = "tool_exec"
    # publish to a shared bus other agents can read (A2A coordination channel)
    BUS_PUBLISH = "bus_publish"


_counter = itertools.count(1)


@dataclass
class Action:
    """A single request from an agent to touch the outside world."""

    agent_id: str
    type: ActionType
    # free-form, type-specific parameters (host, path, tool name, bytes, ...)
    params: dict[str, Any] = field(default_factory=dict)
    # ids of prior actions whose returned data influenced this one.
    # This is how the sentinel tracks provenance / data flow across calls.
    derived_from: list[int] = field(default_factory=list)
    id: int = field(default_factory=lambda: next(_counter))
    ts: float = field(default_factory=time.time)

    def size(self) -> int:
        """Payload size in bytes, for budget accounting."""
        payload = self.params.get("payload", "")
        if isinstance(payload, (bytes, bytearray)):
            return len(payload)
        return len(str(payload).encode("utf-8"))


@dataclass
class Decision:
    allow: bool
    rule: str          # which rule decided this, for the audit log
    reason: str
    # labels the sentinel attached to data this action would return/emit
    taints: set[str] = field(default_factory=set)

    @property
    def deny(self) -> bool:
        return not self.allow
