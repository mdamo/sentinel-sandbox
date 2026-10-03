"""
What happens when the sentinel detects something.

Detection and *response* are separated so the reaction is a reviewed setting,
not hard-coded. A deny always blocks the action (nothing leaves). On top of that
block, a ResponsePolicy maps the rule that fired to an escalation:

    DENY_ONLY         block this action; the agent may keep operating.
    KILL_AGENT        block + permanently deny every future action from this
                      agent (it is considered compromised).
    QUARANTINE_SWARM  block + freeze the WHOLE cell: every agent is denied from
                      now on, pending human review. Use for a confirmed leak,
                      where one agent misbehaving is evidence the swarm may be
                      compromised or colluding.

Every escalation also emits an Alert to an out-of-band sink (a human, a SIEM).
The default policy below preserves the PoC's original behaviour (taint-egress
and canary kill the agent); the demo shows escalating them to quarantine.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class ResponseMode(str, Enum):
    DENY_ONLY = "deny_only"
    KILL_AGENT = "kill_agent"
    QUARANTINE_SWARM = "quarantine_swarm"


# ordering so we can take the max severity if several apply
_SEVERITY = {
    ResponseMode.DENY_ONLY: 0,
    ResponseMode.KILL_AGENT: 1,
    ResponseMode.QUARANTINE_SWARM: 2,
}


@dataclass
class Alert:
    """High-signal event shipped out-of-band the moment a response escalates."""
    ts: float
    agent_id: str
    action_id: int
    rule: str
    reason: str
    mode: ResponseMode

    def line(self) -> str:
        return (f"!! ALERT [{self.mode.value}] agent={self.agent_id} "
                f"a#{self.action_id} rule={self.rule} :: {self.reason}")


AlertSink = Callable[[Alert], None]


@dataclass
class ResponsePolicy:
    """Maps a fired rule -> how hard to react. Unlisted rules use `default`."""
    by_rule: dict[str, ResponseMode] = field(default_factory=dict)
    default: ResponseMode = ResponseMode.DENY_ONLY

    def mode_for(self, rule: str) -> ResponseMode:
        return self.by_rule.get(rule, self.default)

    @staticmethod
    def preserve_original() -> "ResponsePolicy":
        """Backwards-compatible default: taint/canary kill the agent."""
        return ResponsePolicy(by_rule={
            "taint-egress": ResponseMode.KILL_AGENT,
            "canary-tripwire": ResponseMode.KILL_AGENT,
        })

    @staticmethod
    def strict() -> "ResponsePolicy":
        """A stricter stance: any confirmed leak freezes the whole cell."""
        return ResponsePolicy(by_rule={
            "taint-egress": ResponseMode.QUARANTINE_SWARM,
            "canary-tripwire": ResponseMode.QUARANTINE_SWARM,
            "corr-split-payload": ResponseMode.QUARANTINE_SWARM,
            "corr-split-role": ResponseMode.KILL_AGENT,
        })
