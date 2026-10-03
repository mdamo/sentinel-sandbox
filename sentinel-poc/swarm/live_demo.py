"""Run six live Nemotron proposal agents with abstract, mediated tools."""
from __future__ import annotations

import argparse

from run_demo import build_sentinel
from .ai_agents import ToolRegistry, build_ai_agents
from .nemotron import ModelError, NemotronModel


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=None, help="Override the configured model")
    parser.add_argument("--task", default="Produce a short result for the sandbox demo")
    args = parser.parse_args()
    try:
        model = NemotronModel(model=args.model)
        broker = build_sentinel()
        tools = ToolRegistry(broker)
        print(f"Live proposal backend: {model.model}; abstract tools; local process", flush=True)
        # Fetch and validate the entire batch before any tool is submitted.
        proposals = []
        for agent in build_ai_agents(model):
            print(f"Requesting proposals for {agent.agent_id} ({agent.role})", flush=True)
            proposals.append((agent, model.propose(agent.role, args.task)))
        for agent, calls in proposals:
            for call in calls:
                action, decision = tools.submit(agent.agent_id, call)
                print(f"{agent.agent_id}: {action.type.value} -> "
                      f"{'ALLOW' if decision.allow else 'DENY'} {decision.rule}")
        verified = broker.audit.verify()
        print(f"Actions: {len(broker.audit)}; denied: {len(broker.denials())}; "
              f"audit chain verifies: {verified}")
        return 0 if verified else 1
    except ModelError as exc:
        print(f"Live demo failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
