"""AI-agent interfaces with an offline model backend and mediated tools.

A model proposes tool calls; only the deterministic sentinel decides permission.
The bundled backend is scripted, not a language model. Tools express intent only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from sentinel.actions import Action, ActionType, Decision
from sentinel.broker import Broker
from .catalog import AGENT_ROLES, TOOL_TYPES


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
        calls = {
            "researcher": ToolCall("read_file", {"path": "/work/input/task.json"}),
            "writer": ToolCall("write_file", {"path": "/work/tmp/report", "payload": task}),
            "analyst": ToolCall("run_python"),
            "reporter": ToolCall("send_result", {"host": "api.internal.svc", "payload": task}),
            "resolver": ToolCall("resolve_host", {"host": "api.internal.svc"}),
            "coordinator": ToolCall("publish_message", {"payload": task}),
        }
        return [calls[role]]


class ToolRegistry:
    """Six named tools, all routed through Broker.submit; no effect executor."""

    def __init__(self, broker: Broker):
        self.broker = broker

    def submit(self, agent_id: str, call: ToolCall) -> tuple[Action, Decision]:
        if call.name not in TOOL_TYPES:
            raise ValueError(f"unknown tool: {call.name}")
        params = dict(call.arguments)
        if call.name == "run_python":
            params["tool"] = "python"
        action = Action(agent_id, ActionType(TOOL_TYPES[call.name]), params,
                        derived_from=list(call.derived_from))
        return action, self.broker.submit(action)


@dataclass
class AIAgent:
    agent_id: str
    role: str
    model: Model

    def run(self, task: str, tools: ToolRegistry) -> list[tuple[Action, Decision]]:
        return [tools.submit(self.agent_id, call)
                for call in self.model.propose(self.role, task)]


def build_ai_agents(model: Model | None = None) -> tuple[AIAgent, ...]:
    backend = model if model is not None else OfflineModel()
    return tuple(AIAgent(agent_id, role, backend)
                 for agent_id, role in AGENT_ROLES.items())
