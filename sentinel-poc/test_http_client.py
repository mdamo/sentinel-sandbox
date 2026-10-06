"""Repeat-run regressions for the abstract HTTP demo (stdlib only)."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from sentinel.actions import Action, ActionType
from sentinel import serve
from swarm.agent_client import ROLE_ATTEMPTS
from swarm.catalog import AGENT_ROLES


class HTTPClientTests(unittest.TestCase):
    def test_two_client_processes_share_one_server(self):
        broker = serve.default_broker()
        server = serve.ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        env = dict(os.environ, BROKER_URL=
                   f"http://127.0.0.1:{server.server_port}/submit")
        with patch.object(serve, "BROKER", broker), contextlib.redirect_stdout(io.StringIO()):
            worker.start()
            try:
                for _ in range(2):
                    result = subprocess.run(
                        [sys.executable, "-m", "swarm.agent_client"],
                        cwd=Path(__file__).resolve().parent, env=env,
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Completed 6 agent roles", result.stdout)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)
        self.assertEqual(len(broker.audit), 16)
        self.assertEqual(len(broker.denials()), 2)
        self.assertTrue(broker.audit.verify())
        self.assertFalse(broker.monitor.killed)
        self.assertFalse(broker.monitor.quarantined)

    def test_repeat_runs_retain_request_budgets(self):
        broker = serve.default_broker()
        for _ in range(10):
            for agent, role in AGENT_ROLES.items():
                for kind, params, allow, rule in ROLE_ATTEMPTS[role]:
                    decision = broker.submit(Action(agent, ActionType(kind), params))
                    self.assertEqual((decision.allow, decision.rule), (allow, rule))
        decision = broker.submit(Action("agent-1", ActionType.FILE_READ,
                                        {"path": "/work/input/task.json"}))
        self.assertFalse(decision.allow)
        self.assertEqual(decision.rule, "budget-agent")
        self.assertTrue(broker.audit.verify())

    def test_workflow_host_still_enforces_taint_and_quarantine(self):
        broker = serve.default_broker()
        read = Action("agent-1", ActionType.FILE_READ, {"path": "/secrets/key"})
        self.assertTrue(broker.submit(read).allow)
        with contextlib.redirect_stdout(io.StringIO()):
            decision = broker.submit(Action("agent-1", ActionType.NET_SEND,
                {"host": "api.internal.svc", "payload": "secret"}, derived_from=[read.id]))
        self.assertFalse(decision.allow)
        self.assertEqual(decision.rule, "taint-egress")
        decision = broker.submit(Action("agent-2", ActionType.FILE_READ, {"path": "/work/x"}))
        self.assertEqual(decision.rule, "swarm-quarantined")

    def test_unconfigured_host_still_enforces_correlation(self):
        from dataclasses import replace
        broker = serve.default_broker()
        for agent, cap in list(broker.policy.capabilities.items()):
            broker.policy.grant(agent, replace(cap, net_allowlist=cap.net_allowlist | {"other.internal.svc"}))
        self.assertTrue(broker.submit(Action("agent-5", ActionType.DNS_RESOLVE,
                                            {"host": "other.internal.svc"})).allow)
        with contextlib.redirect_stdout(io.StringIO()):
            decision = broker.submit(Action("agent-1", ActionType.NET_SEND,
                                             {"host": "other.internal.svc", "payload": "x"}))
        self.assertFalse(decision.allow)
        self.assertEqual(decision.rule, "corr-split-role")


if __name__ == "__main__":
    unittest.main()
