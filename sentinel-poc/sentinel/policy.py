"""
Deterministic policy layer.

This is the part that must be SIMPLE, TOTAL, and OUTSIDE the model. It takes an
Action plus context and returns allow/deny. No LLM is consulted. No agent output
can change a rule. Given the same action and the same policy, the decision is
always identical and fully explainable by naming the rule that fired.

Design choices that matter:
  * Default deny. An action type or destination not explicitly granted is denied.
  * Capabilities are per-agent. Each agent is granted the narrowest set it needs.
  * Allowlists are by exact host, never by substring, never by binary alone.
    (The OpenAI/HuggingFace escape went through a *permitted* proxy host; so the
    lesson here is that the host allowlist is necessary but not sufficient — the
    stateful monitor in monitor.py is what catches abuse of permitted channels.)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .actions import Action, ActionType, Decision


@dataclass(frozen=True)
class Capability:
    """What a single agent is allowed to attempt at all."""

    allowed_types: frozenset[ActionType]
    # exact hostnames this agent may send to / resolve
    net_allowlist: frozenset[str] = frozenset()
    # exact tool binaries this agent may invoke
    tool_allowlist: frozenset[str] = frozenset()
    # path prefixes the agent may read / write
    read_prefixes: tuple[str, ...] = ()
    write_prefixes: tuple[str, ...] = ()


@dataclass
class Policy:
    """The whole deterministic rulebook."""

    capabilities: dict[str, Capability] = field(default_factory=dict)
    # paths whose contents are considered sensitive; reads of them get tainted.
    sensitive_prefixes: tuple[str, ...] = ()
    # canary / honeytoken paths: any touch is an immediate, unambiguous kill.
    canary_paths: frozenset[str] = frozenset()

    def grant(self, agent_id: str, cap: Capability) -> None:
        self.capabilities[agent_id] = cap

    # -- the single entry point -------------------------------------------
    def evaluate(self, action: Action) -> Decision:
        cap = self.capabilities.get(action.agent_id)
        if cap is None:
            return Decision(False, "no-capability",
                            f"agent {action.agent_id} has no granted capability")

        # Canary check comes first and overrides everything. Touching a
        # honeytoken is never legitimate, so there are no false positives.
        if action.type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            path = action.params.get("path", "")
            if path in self.canary_paths:
                return Decision(False, "canary-tripwire",
                                f"honeytoken {path!r} touched — hard kill")

        if action.type not in cap.allowed_types:
            return Decision(False, "capability-type",
                            f"{action.agent_id} may not perform {action.type.value}")

        handler = {
            ActionType.NET_SEND: self._net,
            ActionType.DNS_RESOLVE: self._dns,
            ActionType.FILE_READ: self._read,
            ActionType.FILE_WRITE: self._write,
            ActionType.TOOL_EXEC: self._tool,
            ActionType.BUS_PUBLISH: self._bus,
        }[action.type]
        return handler(action, cap)

    # -- per-type deterministic checks ------------------------------------
    def _net(self, action: Action, cap: Capability) -> Decision:
        host = action.params.get("host", "")
        if host not in cap.net_allowlist:
            return Decision(False, "egress-allowlist",
                            f"host {host!r} not in allowlist {sorted(cap.net_allowlist)}")
        return Decision(True, "egress-allowlist", f"host {host!r} permitted")

    def _dns(self, action: Action, cap: Capability) -> Decision:
        host = action.params.get("host", "")
        # only allow DNS for hosts the agent could legitimately reach
        base = host.split(".", 1)[-1] if host.count(".") > 1 else host
        if host in cap.net_allowlist or base in cap.net_allowlist:
            return Decision(True, "dns-allowlist", f"resolve {host!r} permitted")
        return Decision(False, "dns-allowlist",
                        f"DNS for {host!r} not permitted (possible covert channel)")

    def _read(self, action: Action, cap: Capability) -> Decision:
        path = action.params.get("path", "")
        if not any(path.startswith(p) for p in cap.read_prefixes):
            return Decision(False, "fs-read-scope", f"read of {path!r} outside granted scope")
        taints: set[str] = set()
        if any(path.startswith(p) for p in self.sensitive_prefixes):
            taints.add(f"sensitive:{path}")
        return Decision(True, "fs-read-scope", f"read {path!r} permitted", taints=taints)

    def _write(self, action: Action, cap: Capability) -> Decision:
        path = action.params.get("path", "")
        if not any(path.startswith(p) for p in cap.write_prefixes):
            return Decision(False, "fs-write-scope", f"write to {path!r} outside granted scope")
        return Decision(True, "fs-write-scope", f"write {path!r} permitted")

    def _tool(self, action: Action, cap: Capability) -> Decision:
        tool = action.params.get("tool", "")
        if tool not in cap.tool_allowlist:
            return Decision(False, "tool-allowlist", f"tool {tool!r} not permitted")
        return Decision(True, "tool-allowlist", f"tool {tool!r} permitted")

    def _bus(self, action: Action, cap: Capability) -> Decision:
        # publishing to the shared bus is allowed by capability; the monitor is
        # what inspects *what* is published for cross-agent collusion signals.
        return Decision(True, "bus-open", "publish permitted (content inspected by monitor)")
