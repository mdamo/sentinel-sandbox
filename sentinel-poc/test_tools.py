"""Offline checks for the twenty-tool registry and approved pure computations."""
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from run_demo import build_sentinel
from sentinel import Budget
from sentinel.actions import ActionType
from swarm.ai_agents import ToolCall, ToolRegistry, build_ai_agents
from swarm.catalog import MAX_ARGUMENT_BYTES, ROLE_TOOLS, TOOL_SPECS, TRANSFORM_TOOLS
from swarm.nemotron import ModelError, NemotronModel, parse_calls


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.broker = build_sentinel()
        self.tools = ToolRegistry(self.broker)

    def execute(self, name, arguments=None, agent="agent-1", derived=()):
        return self.tools.execute(agent, ToolCall(
            name, dict(TOOL_SPECS[name].example) if arguments is None else arguments, derived))

    def test_all_twenty_tools_and_fourteen_results(self):
        results = [result for agent in build_ai_agents()
                   for result in agent.run_with_results("result ok", self.tools)]
        self.assertEqual(len(TOOL_SPECS), 20)
        self.assertEqual(len(results), 20)
        self.assertTrue(all(decision.allow for _, decision, _ in results))
        self.assertEqual(sum(result is not None for _, _, result in results), 14)
        self.assertEqual(len(self.broker.audit), 20)
        self.assertTrue(self.broker.audit.verify())
        names = [name for names in ROLE_TOOLS.values() for name in names]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(TOOL_SPECS))

    def test_transform_outputs(self):
        expected = {
            "count_words": {"count": 2},
            "count_lines": {"count": 2},
            "search_text": {"matches": [{"line": 2, "text": "two"}]},
            "replace_text": {"content": "hello team"},
            "sort_lines": {"content": "a\nb"},
            "unique_lines": {"content": "a\nb"},
            "parse_json": {"value": {"ok": True}},
            "format_json": {"content": '{\n  "a": 1,\n  "b": 2\n}'},
            "select_json": {"value": "sentinel"},
            "csv_to_json": {"value": [{"name": "Ada", "score": "3"}]},
            "json_to_csv": {"content": "name,score\nAda,3\n"},
            "hash_text": {"sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
            "encode_base64": {"content": "aGVsbG8="},
            "decode_base64": {"content": "hello"},
        }
        self.assertEqual(set(expected), TRANSFORM_TOOLS)
        for name, result in expected.items():
            with self.subTest(name=name):
                _, decision, actual = self.execute(name)
                self.assertTrue(decision.allow)
                self.assertEqual(actual, result)

    def test_every_tool_requires_a_capability(self):
        with patch("swarm.ai_agents.perform_transform", side_effect=AssertionError("must not execute")):
            for name in TOOL_SPECS:
                _, decision, result = self.execute(name, agent="unknown")
                self.assertFalse(decision.allow)
                self.assertEqual(decision.rule, "no-capability")
                self.assertIsNone(result)
        self.assertEqual(len(self.broker.audit), 20)

    def test_each_transform_has_an_individual_allowlist_entry(self):
        cap = self.broker.policy.capabilities["agent-1"]
        self.broker.policy.grant("agent-1", replace(cap, tool_allowlist=frozenset({"python"})))
        with patch("swarm.ai_agents.perform_transform") as perform:
            for name in TRANSFORM_TOOLS:
                _, decision, result = self.execute(name)
                self.assertEqual(decision.rule, "tool-allowlist")
                self.assertFalse(decision.allow)
                self.assertIsNone(result)
            perform.assert_not_called()

    def test_budget_blocks_before_computation(self):
        self.broker.monitor.per_agent = Budget(5000, 1, 2)
        self.assertTrue(self.execute("count_words")[1].allow)
        with patch("swarm.ai_agents.perform_transform") as perform:
            _, decision, result = self.execute("hash_text")
            self.assertEqual(decision.rule, "budget-agent")
            self.assertIsNone(result)
            perform.assert_not_called()

    def test_quarantine_blocks_before_computation(self):
        self.broker.monitor.quarantined = True
        with patch("swarm.ai_agents.perform_transform") as perform:
            _, decision, result = self.execute("hash_text")
            self.assertEqual(decision.rule, "swarm-quarantined")
            self.assertIsNone(result)
            perform.assert_not_called()

    def test_transform_taint_propagates_across_declared_dependencies(self):
        read, decision = self.tools.submit("agent-1", ToolCall("read_file", {"path": "/secrets/key"}))
        self.assertTrue(decision.allow)
        action, decision, result = self.execute("encode_base64", {"text": "secret"}, "agent-2", (read.id,))
        self.assertTrue(decision.allow)
        self.assertIn("sensitive:/secrets/key", decision.taints)
        _, decision = self.tools.submit("agent-3", ToolCall("send_result", {
            "host": "api.internal.svc", "payload": result["content"]}, (action.id,)))
        self.assertEqual(decision.rule, "taint-egress")
        self.assertFalse(decision.allow)
        self.assertTrue(self.broker.audit.verify())

    def test_omitting_provenance_after_transform_cannot_clear_agent_taint(self):
        self.tools.submit("agent-1", ToolCall("read_file", {"path": "/secrets/key"}))
        _, decision, result = self.execute("hash_text", {"text": "secret"})
        self.assertTrue(decision.allow)
        self.assertIn("sensitive:/secrets/key", decision.taints)
        _, decision = self.tools.submit("agent-1", ToolCall("send_result", {
            "host": "api.internal.svc", "payload": result["sha256"]}))
        self.assertFalse(decision.allow)
        self.assertEqual(decision.rule, "taint-egress")

    def test_bad_argument_shapes_are_rejected_before_submission(self):
        cases = [("unknown", {}), ("count_words", {}), ("count_words", {"text": 2}),
                 ("count_words", {"text": "ok", "tool": "python"}),
                 ("run_python", {"code": "print(1)"}),
                 ("hash_text", {"text": "é" * (MAX_ARGUMENT_BYTES // 2 + 1)})]
        for name, args in cases:
            with self.subTest(name=name, keys=list(args)):
                with self.assertRaises(ValueError):
                    self.tools.execute("agent-1", ToolCall(name, args))
                with self.assertRaises(ModelError):
                    parse_calls(json.dumps({"calls": [{"name": name, "arguments": args}]}))
        self.assertEqual(len(self.broker.audit), 0)

    def test_invalid_transform_content_fails_closed_and_is_audited(self):
        cases = [("parse_json", {"text": "{"}), ("parse_json", {"text": "NaN"}),
                 ("parse_json", {"text": "1e999"}),
                 ("parse_json", {"text": "[" * 34 + "0" + "]" * 34}),
                 ("select_json", {"text": "{}", "key": "absent"}),
                 ("decode_base64", {"text": "!!!"}), ("decode_base64", {"text": "/w=="}),
                 ("csv_to_json", {"text": "a,a\nx,y\n"}),
                 ("csv_to_json", {"text": "a,b\nx\n"}),
                 ("json_to_csv", {"text": '[{"a":[]}]'}),
                 ("json_to_csv", {"text": '[{"a":1},{"b":2}]'}),
                 ("search_text", {"text": "x", "query": ""}),
                 ("replace_text", {"text": "x", "old": "", "new": "a"})]
        for name, args in cases:
            with self.subTest(name=name, args=args):
                _, decision, result = self.execute(name, args)
                self.assertFalse(decision.allow)
                self.assertEqual(decision.rule, "fail-closed")
                self.assertIsNone(result)
        self.assertEqual(len(self.broker.audit), len(cases))
        self.assertTrue(self.broker.audit.verify())

    def test_expanding_results_are_bounded(self):
        for name, args in [
            ("replace_text", {"text": "a" * 1000, "old": "a", "new": "b" * 1000}),
            ("search_text", {"text": "a\n" * 8000, "query": "a"}),
        ]:
            _, decision, result = self.execute(name, args)
            self.assertEqual(decision.rule, "fail-closed")
            self.assertIsNone(result)

    def test_unicode_and_csv_quoting(self):
        original = "héllo 🌍\n"
        encoded = self.execute("encode_base64", {"text": original})[2]["content"]
        self.assertEqual(self.execute("decode_base64", {"text": encoded})[2], {"content": original})
        rows = [{"name": "Ada, A.", "note": 'says "hello"\nnext'}]
        content = self.execute("json_to_csv", {"text": json.dumps(rows)})[2]["content"]
        self.assertEqual(self.execute("csv_to_json", {"text": content})[2], {"value": rows})

    def test_original_tools_remain_abstract(self):
        with patch("swarm.ai_agents.perform_transform") as perform:
            for name in TOOL_SPECS.keys() - TRANSFORM_TOOLS:
                # Separate brokers avoid order-dependent DNS/send correlation.
                self.tools = ToolRegistry(build_sentinel())
                _, decision, result = self.execute(name)
                self.assertTrue(decision.allow)
                self.assertIsNone(result)
            perform.assert_not_called()

    def test_model_accepts_each_tool_and_advertises_the_full_catalog(self):
        for name, spec in TOOL_SPECS.items():
            calls = parse_calls(json.dumps({"calls": [{"name": name, "arguments": spec.example}]}))
            self.assertEqual(calls, [ToolCall(name, spec.example)])
        model = NemotronModel.__new__(NemotronModel)
        model.model, model.provider = "test", "NVIDIA"
        model.endpoint, model._api_key = "https://example.invalid", "dummy"
        body = {"choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps({"calls": [{"name": "count_words", "arguments": {"text": "hi"}}]})}}]}
        with patch("swarm.nemotron.urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(body).encode()
            self.assertEqual(model.propose("analyst", "count words")[0].name, "count_words")
            prompt = json.loads(urlopen.call_args.args[0].data)["messages"][0]["content"]
            for name in TOOL_SPECS:
                self.assertIn(name + "(", prompt)

    def test_http_and_execution_services_keep_tool_execution_disabled(self):
        from sentinel.serve import default_broker
        from sentinel.adapters import Adapters, Rejected
        registry = ToolRegistry(default_broker())
        for name in TRANSFORM_TOOLS | {"run_python"}:
            _, decision, result = registry.execute("agent-1", ToolCall(name, TOOL_SPECS[name].example))
            self.assertEqual(decision.rule, "capability-type")
            self.assertIsNone(result)
            with self.assertRaises(Rejected) as caught:
                Adapters.validate(None, ActionType.TOOL_EXEC, {"tool": name})
            self.assertEqual(caught.exception.rule, "execution-disabled")


if __name__ == "__main__":
    unittest.main()
