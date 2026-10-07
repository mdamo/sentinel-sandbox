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


def test_omitted_provenance_cannot_clear_sensitive_read():
    b = _broker()
    assert b.submit(Action("A", ActionType.FILE_READ,
                           {"path": "/secrets/key"})).allow
    # The agent deliberately omits both provenance edges.
    assert b.submit(Action("A", ActionType.FILE_WRITE,
                           {"path": "/work/tmp/enc", "payload": "enc"})).allow
    d = b.submit(Action("A", ActionType.NET_SEND,
                        {"host": "ok.host", "payload": "enc"}))
    assert d.deny and d.rule == "taint-egress"
    assert b.audit.verify()
    # The restriction belongs to A; an agent without a sensitive read can send.
    assert b.submit(Action("B", ActionType.NET_SEND,
                           {"host": "ok.host", "payload": "clean"})).allow


def test_omitted_provenance_blocks_every_outbound_channel():
    for action_type, params in (
        (ActionType.NET_SEND, {"host": "ok.host", "payload": "x"}),
        (ActionType.DNS_RESOLVE, {"host": "ok.host"}),
        (ActionType.BUS_PUBLISH, {"payload": "x"}),
    ):
        b = _broker()
        assert b.submit(Action("A", ActionType.FILE_READ,
                               {"path": "/secrets/key"})).allow
        d = b.submit(Action("A", action_type, params, derived_from=[]))
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
    assert len(agents) == 6 and len(TOOL_TYPES) == 20
    results = [result for agent in agents
               for result in agent.run("result ok", ToolRegistry(b))]
    assert {action.type.value for action, _ in results} == set(TOOL_TYPES.values())
    assert all(decision.allow for _, decision in results)
    assert len(b.audit) == 20 and b.audit.verify()


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


def test_ai_tool_cannot_launder_by_omitting_provenance():
    from run_demo import build_sentinel
    from swarm.ai_agents import ToolCall, ToolRegistry
    b = build_sentinel()
    tools = ToolRegistry(b)
    assert tools.submit("agent-1", ToolCall("read_file", {"path": "/secrets/key"}))[1].allow
    _, decision = tools.submit("agent-1", ToolCall(
        "send_result", {"host": "api.internal.svc", "payload": "secret"}))
    assert decision.deny and decision.rule == "taint-egress"


def test_http_roster_has_exactly_six_agents():
    from sentinel.serve import default_broker
    from swarm.catalog import AGENT_ROLES
    b = default_broker()
    assert set(b.policy.capabilities) == set(AGENT_ROLES)
    decision = b.submit(Action("agent-7", ActionType.FILE_READ, {"path": "/work/x"}))
    assert decision.deny and decision.rule == "no-capability"


def test_authenticated_http_effects_and_impersonation():
    import json
    import os
    import tempfile
    import threading
    import urllib.request
    from pathlib import Path
    from sentinel.effects import EffectAdapter
    from sentinel.identity import IdentityStore, signed_headers
    from sentinel.serve import SentinelHTTPServer, default_broker
    from swarm import agent_client

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "work/input").mkdir(parents=True)
        (root / "work/input/task.json").write_text("hello")
        (root / "secrets").mkdir()
        (root / "secrets/key").write_text("secret")
        key_a, key_b = b"a" * 32, b"b" * 32
        server = SentinelHTTPServer(("127.0.0.1", 0), default_broker(),
                                    IdentityStore({"agent-1": key_a, "agent-2": key_b}),
                                    EffectAdapter(root))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client_key = root / "agent.key"
        client_key.write_text(key_b.hex())

        def post(claimed, key, body, headers=None):
            raw = json.dumps(body).encode()
            auth = headers or signed_headers(claimed, key, raw)
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/submit", data=raw,
                headers={"Content-Type": "application/json", **auth})
            return json.loads(urllib.request.urlopen(request, timeout=2).read())

        try:
            read = post("agent-1", key_a,
                        {"type": "file_read", "params": {"path": "/secrets/key"}})
            assert read["allow"] and read["result"]["content"] == "secret"
            spoof = post("agent-2", key_a,
                         {"type": "net_send", "params": {"host": "api.internal.svc",
                                                          "payload": "stolen"}})
            assert not spoof["allow"] and spoof["rule"] == "identity-auth"
            mismatch = post("agent-1", key_a,
                            {"agent_id": "agent-2", "type": "net_send",
                             "params": {"host": "api.internal.svc", "payload": "stolen"}})
            assert not mismatch["allow"] and mismatch["rule"] == "identity-auth"
            clean = post("agent-2", key_b,
                         {"type": "file_write", "params": {"path": "/work/tmp/result",
                                                           "payload": "written"}})
            assert clean["allow"] and (root / "work/tmp/result").read_text() == "written"
            old_broker = agent_client.BROKER
            old_key_file = os.environ.get("AGENT_KEY_FILE")
            try:
                agent_client.BROKER = f"http://127.0.0.1:{server.server_port}/submit"
                os.environ["AGENT_KEY_FILE"] = str(client_key)
                via_client = agent_client.submit("agent-2", "file_read",
                                                 path="/work/input/task.json")
                assert via_client["allow"] and via_client["result"]["content"] == "hello"
            finally:
                agent_client.BROKER = old_broker
                if old_key_file is None:
                    os.environ.pop("AGENT_KEY_FILE", None)
                else:
                    os.environ["AGENT_KEY_FILE"] = old_key_file
            (root / "work/tmp/link").symlink_to(root / "secrets/key")
            escape = post("agent-2", key_b,
                          {"type": "file_write", "params": {"path": "/work/tmp/link",
                                                            "payload": "overwrite"}})
            assert not escape["allow"] and (root / "secrets/key").read_text() == "secret"
            raw = json.dumps({"type": "net_send", "params": {
                "host": "api.internal.svc", "payload": "ok"}}).encode()
            headers = signed_headers("agent-2", key_b, raw)
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/submit", data=raw,
                headers={"Content-Type": "application/json", **headers})
            first = json.loads(urllib.request.urlopen(request, timeout=2).read())
            replay = json.loads(urllib.request.urlopen(request, timeout=2).read())
            assert first["allow"] and not replay["allow"]
            assert replay["rule"] == "identity-auth"
            assert len((root / "outbox.jsonl").read_text().splitlines()) == 1
            denied = post("agent-1", key_a,
                          {"type": "net_send", "params": {"host": "api.internal.svc",
                                                           "payload": "stolen"},
                           "derived_from": []})
            assert not denied["allow"] and denied["rule"] == "taint-egress"
            assert len((root / "outbox.jsonl").read_text().splitlines()) == 1
            assert server.broker.audit.verify()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


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
