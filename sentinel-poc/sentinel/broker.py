"""
The broker is the sentinel's enforcement point: the ONE path every agent action
must cross. In the containerised deployment (see deploy/) this is a process in a
separate container; the agent container has no other way out. Here it is an
in-process object so the whole thing runs as a single `python run_demo.py`.

Enforcement order, mediating every call (complete mediation):
    1. deterministic policy (allow in isolation?)
    2. stateful monitor (allow given everything seen so far, per-agent + swarm?)
    3. only if both allow is the action considered authorized.

The broker can invoke a trusted adapter only after an allow. The local demo
uses submit() without an adapter; the HTTP server uses execute() with its
host-owned adapter. Every final decision is appended to the audit log.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Callable

from .actions import Action, Decision
from .monitor import Monitor
from .policy import Policy

GENESIS = "0" * 64  # prev_hash of the first entry


@dataclass
class AuditEntry:
    action: Action
    decision: Decision
    prev_hash: str = GENESIS
    hash: str = ""

    def record(self) -> dict:
        """The canonical, hashed content of this entry."""
        return {
            "action_id": self.action.id,
            "agent_id": self.action.agent_id,
            "type": getattr(self.action.type, "value", str(self.action.type)),
            "params": self.action.params,
            "derived_from": self.action.derived_from,
            "allow": self.decision.allow,
            "rule": self.decision.rule,
            "reason": self.decision.reason,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        blob = json.dumps(self.record(), sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()

    def line(self) -> str:
        d = self.decision
        verb = "ALLOW" if d.allow else "DENY "
        p = self.action.params
        detail = p.get("host") or p.get("path") or p.get("tool") or p.get("topic") or ""
        return (f"[{verb}] a#{self.action.id:<3} {self.action.agent_id:<10} "
                f"{self.action.type.value:<12} {str(detail):<22} "
                f":: {d.rule}: {d.reason}")


class AuditLog:
    """Append-only, hash-chained log. Any edit to a past entry breaks the chain,
    so `verify()` fails — tamper-evident. In production each entry is also
    shipped out-of-band so a compromised sandbox can't erase its own trail."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(self, action: Action, decision: Decision) -> AuditEntry:
        prev = self._entries[-1].hash if self._entries else GENESIS
        entry = AuditEntry(copy.deepcopy(action), copy.deepcopy(decision), prev_hash=prev)
        entry.hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = GENESIS
        for e in self._entries:
            if e.prev_hash != prev or e.hash != e.compute_hash():
                return False
            prev = e.hash
        return True

    # make it behave like the old list for existing callers
    def __iter__(self):
        return iter(self._entries)

    def __getitem__(self, i):
        return self._entries[i]

    def __len__(self):
        return len(self._entries)


class Broker:
    def __init__(self, policy: Policy, monitor: Monitor) -> None:
        self.policy = policy
        self.monitor = monitor
        self.audit = AuditLog()
        self.fail_closed = True
        # Reentrant: the execution runtime borrows this lock for its own
        # state transitions while the broker reviews an action.
        self.lock = threading.RLock()

    def submit(self, action: Action) -> Decision:
        return self.execute(action)[0]

    def execute(self, action: Action,
                effect: Callable[[Action], dict] | None = None) -> tuple[Decision, dict | None]:
        """Serialize review and host effect; audit the final outcome.

        The action is snapshotted so a caller cannot mutate what was reviewed
        and audited after the fact.
        """
        with self.lock:
            return self._execute_locked(copy.deepcopy(action), effect)

    def _execute_locked(self, action: Action,
                        effect: Callable[[Action], dict] | None) -> tuple[Decision, dict | None]:
        result = None
        try:
            policy_decision = self.policy.evaluate(action)
            decision = self.monitor.review(action, policy_decision)
            if decision.allow:
                if effect is not None:
                    result = effect(action)
                self.monitor.record_result(action, decision)
        except Exception as exc:  # any internal fault -> deny, never allow
            if not self.fail_closed:
                raise
            decision = Decision(False, "fail-closed",
                                f"sentinel internal error, denying: {exc!r}")
        self.audit.append(action, decision)
        return decision, result

    # convenience for stats / tests
    def denials(self) -> list[AuditEntry]:
        return [e for e in self.audit if e.decision.deny]
