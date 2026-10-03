"""
Tests asserting each escape pattern is denied by the EXPECTED rule. Runnable
with `pytest` or directly with `python test_sentinel.py`. No external deps.
"""

from __future__ import annotations

from sentinel import (Broker, Budget, Capability, Monitor, Policy,
                      ResponseMode, ResponsePolicy)
from sentinel.actions import Action, ActionType


def _broker(**monitor_kw) -> Broker:
    policy = Policy(sensitive_prefixes=("/secrets/",),
                    canary_paths=frozenset({"/secrets/.honeytoken"}))
    cap = Capability(
        allowed_types=frozenset(ActionType),
        net_allowlist=frozenset({"ok.host"}),
        tool_allowlist=frozenset({"python"}),
        read_prefixes=("/work/", "/secrets/"),
        write_prefixes=("/work/tmp/",),
    )
    for a in ("A", "B", "C", "D"):
        policy.grant(a, cap)
    mon = Monitor(
        per_agent=Budget(monitor_kw.get("abytes", 5000), 20, 2),
        per_swarm=Budget(monitor_kw.get("sbytes", 50000), 100, 3),
        split_payload_threshold=monitor_kw.get("split", 3),
        response=monitor_kw.get("response"),
        on_alert=monitor_kw.get("on_alert"),
    )
    return Broker(policy, mon)


def test_benign_allowed():
    b = _broker()
    assert b.submit(Action("A", ActionType.FILE_READ, {"path": "/work/x"})).allow
    assert b.submit(Action("A", ActionType.NET_SEND,
                           {"host": "ok.host", "payload": "hi"})).allow


def test_unknown_agent_denied():
    b = _broker()
    d = b.submit(Action("ghost", ActionType.NET_SEND, {"host": "ok.host"}))
    assert d.deny and d.rule == "no-capability"


def test_direct_exfil_denied():
    b = _broker()
    d = b.submit(Action("A", ActionType.NET_SEND, {"host": "evil.host", "payload": "x"}))
    assert d.deny and d.rule == "egress-allowlist"


def test_laundered_flow_denied_by_taint():
    b = _broker()
    r = Action("A", ActionType.FILE_READ, {"path": "/secrets/key"})
    assert b.submit(r).allow
    w = Action("A", ActionType.FILE_WRITE, {"path": "/work/tmp/enc"}, derived_from=[r.id])
    assert b.submit(w).allow
    s = Action("A", ActionType.NET_SEND,
               {"host": "ok.host", "payload": "enc"}, derived_from=[w.id])
    d = b.submit(s)
    assert d.deny and d.rule == "taint-egress"


def test_dns_covert_denied():
    b = _broker()
    d = b.submit(Action("A", ActionType.DNS_RESOLVE, {"host": "data.evil.zone"}))
    assert d.deny and d.rule == "dns-allowlist"


def test_allowlisted_abuse_hits_budget():
    b = _broker(abytes=5000)
    big = "x" * 4000
    assert b.submit(Action("A", ActionType.NET_SEND, {"host": "ok.host", "payload": big})).allow
    d = b.submit(Action("A", ActionType.NET_SEND, {"host": "ok.host", "payload": big}))
    assert d.deny and d.rule == "budget-agent"


def test_canary_kills_agent():
    b = _broker()
    d = b.submit(Action("A", ActionType.FILE_READ, {"path": "/secrets/.honeytoken"}))
    assert d.deny and d.rule == "canary-tripwire"
    # every subsequent action from A is denied
    d2 = b.submit(Action("A", ActionType.NET_SEND, {"host": "ok.host", "payload": "x"}))
    assert d2.deny and d2.rule == "agent-killed"


def test_split_role_denied():
    b = _broker()
    assert b.submit(Action("A", ActionType.DNS_RESOLVE, {"host": "ok.host"})).allow
    d = b.submit(Action("B", ActionType.NET_SEND, {"host": "ok.host", "payload": "x"}))
    assert d.deny and d.rule == "corr-split-role"


def test_split_payload_denied():
    b = _broker(split=3)
    last = None
    for a in ("A", "B", "C"):
        last = b.submit(Action(a, ActionType.NET_SEND, {"host": "ok.host", "payload": "s"}))
    assert last.deny and last.rule == "corr-split-payload"


def _leak(b: Broker, agent: str = "A"):
    """Drive a laundered leak that trips taint-egress for `agent`."""
    r = Action(agent, ActionType.FILE_READ, {"path": "/secrets/key"})
    b.submit(r)
    return b.submit(Action(agent, ActionType.NET_SEND,
                           {"host": "ok.host", "payload": "x"}, derived_from=[r.id]))


def test_response_deny_only_does_not_kill():
    pol = ResponsePolicy(by_rule={"taint-egress": ResponseMode.DENY_ONLY})
    b = _broker(response=pol)
    d = _leak(b)
    assert d.deny and d.rule == "taint-egress"
    # agent NOT killed: a clean action still goes through
    assert b.submit(Action("A", ActionType.FILE_READ, {"path": "/work/x"})).allow
    assert b.monitor.alerts == []  # deny-only emits no alert


def test_response_kill_agent():
    pol = ResponsePolicy(by_rule={"taint-egress": ResponseMode.KILL_AGENT})
    b = _broker(response=pol)
    assert _leak(b).deny
    d = b.submit(Action("A", ActionType.FILE_READ, {"path": "/work/x"}))
    assert d.deny and d.rule == "agent-killed"
    # but a different agent is unaffected
    assert b.submit(Action("B", ActionType.FILE_READ, {"path": "/work/x"})).allow
    assert len(b.monitor.alerts) == 1 and b.monitor.alerts[0].mode == ResponseMode.KILL_AGENT


def test_response_quarantine_swarm_freezes_everyone():
    pol = ResponsePolicy(by_rule={"taint-egress": ResponseMode.QUARANTINE_SWARM})
    b = _broker(response=pol)
    assert _leak(b, "A").deny
    assert b.monitor.quarantined
    # EVERY other agent is now denied with swarm-quarantined
    for other in ("B", "C", "D"):
        d = b.submit(Action(other, ActionType.FILE_READ, {"path": "/work/x"}))
        assert d.deny and d.rule == "swarm-quarantined"


def test_alert_hook_fires_out_of_band():
    received = []
    pol = ResponsePolicy(by_rule={"canary-tripwire": ResponseMode.QUARANTINE_SWARM})
    b = _broker(response=pol, on_alert=received.append)
    b.submit(Action("A", ActionType.FILE_READ, {"path": "/secrets/.honeytoken"}))
    assert len(received) == 1
    assert received[0].rule == "canary-tripwire"
    assert received[0].mode == ResponseMode.QUARANTINE_SWARM


def test_audit_chain_verifies_and_detects_tampering():
    b = _broker()
    b.submit(Action("A", ActionType.FILE_READ, {"path": "/work/x"}))
    _leak(b)
    assert b.audit.verify()                      # intact chain verifies
    # tamper: flip a past decision from deny to allow
    b.audit[-1].decision.rule = "egress-allowlist"
    assert not b.audit.verify()                  # chain now broken


def test_fail_closed_on_internal_error():
    b = _broker()
    # a malformed action (type not an ActionType) should deny, never allow
    bad = Action("A", "garbage", {})  # type: ignore[arg-type]
    d = b.submit(bad)
    assert d.deny


def test_six_ai_agents_and_tools_are_mediated():
    from run_demo import build_sentinel
    from swarm.ai_agents import ToolRegistry, build_ai_agents
    from swarm.catalog import TOOL_TYPES
    b = build_sentinel()
    agents = build_ai_agents()
    assert len(agents) == 6 and len(TOOL_TYPES) == 6
    results = [result for agent in agents
               for result in agent.run("result ok", ToolRegistry(b))]
    assert {action.type.value for action, _ in results} == set(TOOL_TYPES.values())
    assert all(decision.allow for _, decision in results)
    assert len(b.audit) == 6 and b.audit.verify()


def test_ai_model_cannot_override_sentinel():
    from run_demo import build_sentinel
    from swarm.ai_agents import AIAgent, ToolCall, ToolRegistry

    class UnsafeModel:
        def propose(self, role, task):
            return [ToolCall("send_result", {"host": "evil.host", "payload": "x"})]

    b = build_sentinel()
    result = AIAgent("agent-1", "researcher", UnsafeModel()).run("task", ToolRegistry(b))
    assert result[0][1].deny and result[0][1].rule == "egress-allowlist"
    assert len(b.audit) == 1 and b.audit.verify()


def test_ai_tools_preserve_taint_provenance():
    from run_demo import build_sentinel
    from swarm.ai_agents import ToolCall, ToolRegistry
    b = build_sentinel()
    tools = ToolRegistry(b)
    action, decision = tools.submit("agent-1", ToolCall("read_file", {"path": "/secrets/key"}))
    assert decision.allow
    _, decision = tools.submit("agent-1", ToolCall(
        "send_result", {"host": "api.internal.svc", "payload": "secret"}, (action.id,)))
    assert decision.deny and decision.rule == "taint-egress"


def test_http_roster_has_exactly_six_agents():
    from sentinel.serve import default_broker
    from swarm.catalog import AGENT_ROLES
    b = default_broker()
    assert set(b.policy.capabilities) == set(AGENT_ROLES)
    decision = b.submit(Action("agent-7", ActionType.FILE_READ, {"path": "/work/x"}))
    assert decision.deny and decision.rule == "no-capability"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} tests passed")
    raise SystemExit(0 if passed == len(fns) else 1)
