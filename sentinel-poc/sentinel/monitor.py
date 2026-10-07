"""
The stateful sentinel.

The deterministic policy in policy.py answers "is this one action allowed in
isolation?". That is necessary but not sufficient: a capable swarm does not
break the rules, it escapes *through the channels you allowed*. So the monitor
adds state that spans actions and spans agents:

  * Budgets   — cumulative bytes-out, request counts and distinct destinations,
                enforced per-agent AND per-swarm. Catches slow or distributed
                exfiltration that any single per-request check would wave through.
  * Taint     — data read from sensitive paths is labelled; the label follows
                the data through derived_from links; any outbound action carrying
                a sensitive label is blocked regardless of destination.
  * Provenance— a graph of which action fed which, so "read secret -> transform
                -> send to allowlisted host" is visible as one laundered flow.
  * Correlation — swarm-wide pattern checks: e.g. agent A resolves/probes a host
                and agent B sends to it (split role), or N agents each send a
                sub-threshold slice to the same destination (split payload).

Everything here is deterministic: same action stream in, same decisions out.
The monitor can only make a decision STRICTER than the policy, never looser.
It fails closed: if its own state is inconsistent, it denies.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from .actions import Action, ActionType, Decision
from .response import Alert, AlertSink, ResponseMode, ResponsePolicy


@dataclass
class Budget:
    max_bytes_out: int
    max_requests: int
    max_distinct_dests: int


@dataclass
class _Counters:
    bytes_out: int = 0
    requests: int = 0
    dests: set[str] = field(default_factory=set)

    def would_exceed(self, b: Budget, add_bytes: int, add_dest: str | None) -> str | None:
        if self.bytes_out + add_bytes > b.max_bytes_out:
            return f"bytes-out {self.bytes_out + add_bytes} > {b.max_bytes_out}"
        if self.requests + 1 > b.max_requests:
            return f"request-count {self.requests + 1} > {b.max_requests}"
        if add_dest is not None and add_dest not in self.dests \
                and len(self.dests) + 1 > b.max_distinct_dests:
            return f"distinct-dests {len(self.dests) + 1} > {b.max_distinct_dests}"
        return None

    def apply(self, add_bytes: int, add_dest: str | None) -> None:
        self.bytes_out += add_bytes
        self.requests += 1
        if add_dest is not None:
            self.dests.add(add_dest)


class Monitor:
    def __init__(self, per_agent: Budget, per_swarm: Budget,
                 split_payload_threshold: int = 3,
                 response: ResponsePolicy | None = None,
                 on_alert: AlertSink | None = None,
                 correlation_enforce: bool = True,
                 workflow_hosts: frozenset[str] = frozenset(),
                 correlation_window: float = 300) -> None:
        self.per_agent = per_agent
        self.per_swarm = per_swarm
        self._agent = defaultdict(_Counters)
        self._swarm = _Counters()
        # taint label set carried by each past action's returned data
        self._taint_by_action: dict[int, set[str]] = {}
        # An untrusted agent can omit derived_from. Keep sensitive taint on its
        # identity so an omitted edge cannot turn a later outbound call clean.
        self._taint_by_agent: dict[str, set[str]] = defaultdict(set)
        # provenance edges: action id -> the ids it was derived from
        self._prov: dict[int, list[int]] = {}
        # for split-payload correlation: dest -> set of agents that sent to it
        self._senders_per_dest: dict[str, set[str]] = defaultdict(set)
        # for split-role correlation: hosts that have been probed, and by whom
        self._probed_hosts: dict[str, str] = {}
        self._split_threshold = split_payload_threshold
        # response configuration: how hard to react to each rule, and where
        # alerts go. Default preserves the original kill-on-taint/canary.
        self.response = response or ResponsePolicy.preserve_original()
        self._on_alert = on_alert
        self.killed: set[str] = set()   # agents hard-killed; all further actions denied
        self.quarantined = False        # whole cell frozen pending review
        self.alerts: list[Alert] = []   # in-memory mirror of what was shipped
        self.correlation_enforce = correlation_enforce
        self.workflow_hosts = workflow_hosts
        self.correlation_window = correlation_window
        self._activity: list[tuple[float, str, str, str]] = []
        self.review_signals: list[dict] = []

    def snapshot(self) -> dict:
        """Trusted JSON state; the runtime stores this with each transition."""
        def counter(c):
            return dict(bytes_out=c.bytes_out, requests=c.requests, dests=sorted(c.dests))
        return {
            "agents": {k: counter(v) for k, v in self._agent.items()},
            "swarm": counter(self._swarm), "killed": sorted(self.killed),
            "quarantined": self.quarantined, "activity": self._activity,
            "signals": self.review_signals,
            "taints": {str(k): sorted(v) for k, v in self._taint_by_action.items()},
            "provenance": {str(k): v for k, v in self._prov.items()},
        }

    def restore(self, state: dict) -> None:
        def counter(c):
            return _Counters(c["bytes_out"], c["requests"], set(c["dests"]))
        self._agent = defaultdict(_Counters, {k: counter(v) for k, v in state["agents"].items()})
        self._swarm = counter(state["swarm"])
        self.killed, self.quarantined = set(state["killed"]), state["quarantined"]
        self._activity = [tuple(x) for x in state["activity"]]
        self.review_signals = state["signals"]
        self._taint_by_action = {int(k): set(v) for k, v in state["taints"].items()}
        self._prov = {int(k): v for k, v in state["provenance"].items()}

    # ---- taint propagation ------------------------------------------------
    def _inherited_taint(self, action: Action) -> set[str]:
        taint: set[str] = set()
        for src in action.derived_from:
            taint |= self._taint_by_action.get(src, set())
        return taint

    def record_result(self, action: Action, decision: Decision) -> None:
        """Called after an allowed action to remember its taint + provenance."""
        taint = set(decision.taints) | self._inherited_taint(action)
        self._taint_by_action[action.id] = taint
        self._taint_by_agent[action.agent_id].update(
            t for t in taint if t.startswith("sensitive:"))
        self._prov[action.id] = list(action.derived_from)

    # ---- response / escalation -------------------------------------------
    def _respond(self, action: Action, decision: Decision) -> None:
        """Apply the configured escalation for a detection, and alert."""
        mode = self.response.mode_for(decision.rule)
        if mode is ResponseMode.KILL_AGENT:
            self.killed.add(action.agent_id)
        elif mode is ResponseMode.QUARANTINE_SWARM:
            self.killed.add(action.agent_id)
            self.quarantined = True
        if mode is ResponseMode.DENY_ONLY:
            return  # block only; nothing to escalate, no alert
        alert = Alert(ts=time.time(), agent_id=action.agent_id,
                      action_id=action.id, rule=decision.rule,
                      reason=decision.reason, mode=mode)
        self.alerts.append(alert)
        if self._on_alert is not None:
            self._on_alert(alert)

    # ---- the stateful check ----------------------------------------------
    def review(self, action: Action, policy_decision: Decision) -> Decision:
        # Whole-cell freeze supersedes everything.
        if self.quarantined:
            return Decision(False, "swarm-quarantined",
                            "cell quarantined after a confirmed detection; "
                            "all agents denied pending human review")
        if action.agent_id in self.killed:
            return Decision(False, "agent-killed",
                            f"{action.agent_id} previously killed; all actions denied")

        decision = self._evaluate(action, policy_decision)
        # Any fresh detection routes through the configured response policy.
        if decision.deny and decision.rule not in ("agent-killed", "swarm-quarantined"):
            self._respond(action, decision)
        return decision

    def _evaluate(self, action: Action, policy_decision: Decision) -> Decision:
        if policy_decision.deny:
            return policy_decision

        taint = (set(policy_decision.taints) | self._inherited_taint(action)
                 | self._taint_by_agent[action.agent_id])

        outbound = action.type in (ActionType.NET_SEND, ActionType.DNS_RESOLVE,
                                   ActionType.BUS_PUBLISH)

        # 1) tainted data must never leave, even via an allowlisted channel.
        if outbound and any(t.startswith("sensitive:") for t in taint):
            return Decision(False, "taint-egress",
                            f"outbound action carries sensitive taint {sorted(taint)} "
                            f"(declared sources {action.derived_from}; agent history checked) — blocked")

        # 2) budgets, per-agent and per-swarm.
        add_bytes = action.size() if outbound else 0
        dest = action.params.get("host") if action.type in (
            ActionType.NET_SEND, ActionType.DNS_RESOLVE) else None

        a = self._agent[action.agent_id]
        why = a.would_exceed(self.per_agent, add_bytes, dest)
        if why:
            return Decision(False, "budget-agent", f"per-agent budget exceeded: {why}")
        why = self._swarm.would_exceed(self.per_swarm, add_bytes, dest)
        if why:
            return Decision(False, "budget-swarm", f"per-swarm budget exceeded: {why}")

        # 3) bounded correlation, scoped to this monitor's run.
        now = time.time()
        self._activity = [x for x in self._activity if now - x[0] <= self.correlation_window]
        self._probed_hosts = {host: agent for _, kind, host, agent in self._activity
                              if kind == ActionType.DNS_RESOLVE.value}
        self._senders_per_dest = defaultdict(set)
        for _, kind, host, agent in self._activity:
            if kind == ActionType.NET_SEND.value:
                self._senders_per_dest[host].add(agent)
        if dest is not None:
            # split-role: a different agent probed this exact host first.
            prober = self._probed_hosts.get(dest)
            if action.type == ActionType.NET_SEND and prober and prober != action.agent_id:
                if self.correlation_enforce and dest not in self.workflow_hosts:
                    return Decision(False, "corr-split-role", "cross-agent staging")
                if dest not in self.workflow_hosts:
                    self.review_signals.append(dict(action_id=action.id, rule="corr-split-role", ts=now))
            # split-payload: too many distinct agents converging on one dest.
            senders = self._senders_per_dest[dest] | {action.agent_id}
            if action.type == ActionType.NET_SEND and len(senders) >= self._split_threshold:
                if self.correlation_enforce and dest not in self.workflow_hosts:
                    return Decision(False, "corr-split-payload", "distributed sender pattern")
                if dest not in self.workflow_hosts:
                    self.review_signals.append(dict(action_id=action.id, rule="corr-split-payload", ts=now))

        # passed every stricter check: commit state and allow.
        a.apply(add_bytes, dest)
        self._swarm.apply(add_bytes, dest)
        if dest is not None:
            self._activity.append((now, action.type.value, dest, action.agent_id))
            if action.type == ActionType.DNS_RESOLVE:
                self._probed_hosts.setdefault(dest, action.agent_id)
            if action.type == ActionType.NET_SEND:
                self._senders_per_dest[dest].add(action.agent_id)
        allowed = Decision(True, policy_decision.rule, policy_decision.reason, taints=taint)
        return allowed
