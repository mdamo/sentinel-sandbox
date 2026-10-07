"""AI-agent interfaces with an offline model backend and mediated tools.

A model proposes tool calls; only the deterministic sentinel decides permission.
The bundled backend is scripted, not a language model. Tools express intent only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from sentinel.actions import Action, ActionType, Decision
from sentinel.broker import Broker
from .catalog import AGENT_ROLES, ROLE_TOOLS, TOOL_SPECS, TRANSFORM_TOOLS, validate_arguments
from .transforms import perform_transform


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    derived_from: tuple[int, ...] = ()


class Model(Protocol):
    def propose(self, role: str, task: str) -> list[ToolCall]:
        """Return proposed tool calls, without executing them."""
        ...


class OfflineModel:
    """Explicit simulation for reproducible runs without credentials."""

    def propose(self, role: str, task: str) -> list[ToolCall]:
        calls = []
        for name in ROLE_TOOLS[role]:
            arguments = dict(TOOL_SPECS[name].example)
            if "payload" in arguments:
                arguments["payload"] = task
            calls.append(ToolCall(name, arguments))
        return calls


class ToolRegistry:
    """Twenty mediated tools; submit intents or execute fixed in-memory utilities.

    The original six tools remain abstract in this local registry. Real external
    effects belong to the separately authenticated HTTP/execution services.
    """

    def __init__(self, broker: Broker):
        self.broker = broker

    def _action(self, agent_id: str, call: ToolCall) -> Action:
        validate_arguments(call.name, call.arguments)
        params = dict(call.arguments)
        spec = TOOL_SPECS[call.name]
        if spec.operation:
            params["tool"] = spec.operation
        return Action(agent_id, ActionType(spec.action_type), params,
                      derived_from=list(call.derived_from))

    def submit(self, agent_id: str, call: ToolCall) -> tuple[Action, Decision]:
        action = self._action(agent_id, call)
        return action, self.broker.submit(action)

    def execute(self, agent_id: str, call: ToolCall) -> tuple[Action, Decision, dict | None]:
        """Return a computed result only after policy and monitor approval.

        Non-transform tools receive an abstract decision and a None result.
        Malformed arguments raise ValueError before submission. Computation
        failures are audited as fail-closed denials by the broker.
        """
        action = self._action(agent_id, call)
        effect = perform_transform if call.name in TRANSFORM_TOOLS else None
        decision, result = self.broker.execute(action, effect)
        return action, decision, result


@dataclass
class AIAgent:
    agent_id: str
    role: str
    model: Model

    def run(self, task: str, tools: ToolRegistry) -> list[tuple[Action, Decision]]:
        return [tools.submit(self.agent_id, call)
                for call in self.model.propose(self.role, task)]

    def run_with_results(self, task: str, tools: ToolRegistry) -> list[tuple[Action, Decision, dict | None]]:
        return [tools.execute(self.agent_id, call)
                for call in self.model.propose(self.role, task)]


def build_ai_agents(model: Model | None = None) -> tuple[AIAgent, ...]:
    backend = model if model is not None else OfflineModel()
    return tuple(AIAgent(agent_id, role, backend)
                 for agent_id, role in AGENT_ROLES.items())
