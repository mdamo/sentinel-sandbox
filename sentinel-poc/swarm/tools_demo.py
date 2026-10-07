"""Exercise all twenty tools and compute the fourteen in-memory utilities.

Run: python3 -m swarm.tools_demo
The six original tools return abstract decisions, not external effects.
"""
import json

from run_demo import build_sentinel
from .ai_agents import ToolRegistry, build_ai_agents
from .catalog import TOOL_SPECS, TRANSFORM_TOOLS


def main():
    broker = build_sentinel()
    registry = ToolRegistry(broker)
    computed = 0
    allowed = 0
    for agent in build_ai_agents():
        for action, decision, result in agent.run_with_results("result ok", registry):
            name = action.params.get("tool", action.type.value)
            print(f"{agent.agent_id} {name}: {'ALLOW' if decision.allow else 'DENY'} ({decision.rule})")
            print("  " + (json.dumps(result, ensure_ascii=False) if result is not None else "abstract request only"))
            computed += result is not None
            allowed += decision.allow
    verified = broker.audit.verify()
    print(f"Tools: {allowed}/{len(TOOL_SPECS)} allowed; computed: {computed}; audit verified: {verified}")
    return 0 if allowed == len(TOOL_SPECS) and computed == len(TRANSFORM_TOOLS) and verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
