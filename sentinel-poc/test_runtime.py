"""Controlled Linux fixtures for trusted execution, concurrency and recovery."""
from __future__ import annotations

import concurrent.futures
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sentinel.actions import Action, ActionType
from sentinel.adapters import Adapters, Endpoint
from sentinel.execution_service import Handler, UnixServer, TLSServer, load_runtime
from sentinel.monitor import Budget
from sentinel.policy import Policy, Capability
from sentinel.runtime import Identity, Runtime
from sentinel.storage import Store

TOKENS = {name: name * 40 for name in ("A", "B", "C", "Z")}
AUDIT_KEY = b"test-only-audit-key-do-not-use-in-production" * 2


class LocalService(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.received.append(raw)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/result")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = b"accepted:" + raw
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


class Fixture:
    def __init__(self, *, capability_only=False, agent_bytes=100000, swarm_bytes=1000000,
                 workflows=frozenset(), timeout=3):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "workspace"
        (self.root / "work/input").mkdir(parents=True)
        (self.root / "work/tmp").mkdir()
        (self.root / "secrets").mkdir()
        (self.root / "work/input/public").write_text("public task")
        (self.root / "secrets/key").write_text("fixture-sensitive-value")
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), LocalService)
        self.http.received = []
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.policy = Policy(sensitive_prefixes=("secrets",), canary_paths=frozenset({"secrets/canary"}))
        cap = Capability(frozenset(ActionType), frozenset({"127.0.0.1"}),
                         frozenset({"python"}), ("work", "secrets"), ("work/tmp",))
        for agent in ("A", "B", "C"):
            self.policy.grant(agent, cap)
        self.endpoints = {
            name: Endpoint("127.0.0.1", self.http.server_port, "http", route=route,
                           allowed_ips=("127.0.0.1",), response_sensitive=False)
            for name, route in (("result", "/result"), ("redirect", "/redirect"))}
        self.credentials = {TOKENS[a]: Identity(a, "swarm", "run", a == "Z") for a in TOKENS}
        self.kw = dict(swarm="swarm", run="run", policy_version="test-v1", audit_key=AUDIT_KEY,
                       per_agent=Budget(agent_bytes, 1000, 10), per_swarm=Budget(swarm_bytes, 10000, 10),
                       share_pairs=frozenset({("A", "B")}), topics=frozenset({"results"}),
                       endpoint_grants={a: frozenset(self.endpoints) for a in ("A", "B", "C")},
                       workflow_hosts=workflows, capability_only=capability_only)
        self.timeout = timeout
        self.runtime = None
        self.open()

    def open(self):
        self.runtime = Runtime(self.policy, Adapters(str(self.root), self.endpoints, timeout=self.timeout),
                               Store(str(self.base / "state.sqlite")), self.credentials, **self.kw)

    def restart(self):
        self.runtime.close()
        self.open()

    def request(self, agent="A", kind="file_read", params=None, rid=None, **extra):
        return self.runtime.execute(TOKENS[agent], dict(
            request_id=rid or str(time.monotonic_ns()), type=kind,
            params=params if params is not None else {"path": "work/input/public"}, **extra))

    def incident(self):
        return self.runtime.state.get("active_incident") or self.runtime.store.db.execute("SELECT max(seq) FROM audit").fetchone()[0]

    def close(self):
        if self.runtime:
            self.runtime.close()
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class RuntimeTests(unittest.TestCase):
    def test_real_benign_read_transform_send(self):
        with Fixture() as f:
            read = f.request()
            self.assertEqual(read["result"]["data"], "public task")
            transformed = read["result"]["data"].upper()
            out = f.request(kind="net_send", params={"endpoint": "result", "payload": transformed},
                            dependencies=[read["handle"]])
            self.assertTrue(out["allow"])
            self.assertEqual(out["result"]["data"], "accepted:PUBLIC TASK")
            self.assertEqual(f.http.received, [b"PUBLIC TASK"])
            self.assertGreater(out["reserved_bytes"], len(transformed))

    def test_authentication_impersonation_and_admin_role(self):
        with Fixture() as f:
            body = dict(request_id="x", type="file_write", params={"path": "work/tmp/x", "payload": "x"})
            self.assertEqual(f.runtime.execute("invalid", body)["rule"], "authentication")
            self.assertEqual(f.runtime.execute(TOKENS["A"], dict(body, agent_id="B"))["rule"], "identity-mismatch")
            self.assertEqual(f.runtime.execute(TOKENS["Z"], body)["rule"], "agent-role-required")
            self.assertFalse((f.root / "work/tmp/x").exists())

    def test_omitted_provenance_and_restart_cannot_remove_taint(self):
        with Fixture() as f:
            self.assertTrue(f.request(params={"path": "secrets/key"})["allow"])
            f.restart()
            out = f.request(kind="net_send", params={"endpoint": "result", "payload": "copied literal"})
            self.assertEqual(out["rule"], "taint-egress")
            self.assertEqual(f.http.received, [])
            f.restart()
            self.assertEqual(f.request("B")["rule"], "swarm-quarantined")

    def test_sensitive_file_write_taints_other_reader(self):
        with Fixture() as f:
            f.request(params={"path": "secrets/key"})
            self.assertTrue(f.request(kind="file_write", params={"path": "work/tmp/shared", "payload": "derived"})["allow"])
            f.request("B", params={"path": "work/tmp/shared"})
            self.assertEqual(f.request("B", "net_send", {"endpoint": "result", "payload": "derived"})["rule"], "taint-egress")
            self.assertEqual(f.http.received, [])

    def test_forged_cross_agent_and_cross_run_handles(self):
        with Fixture() as f:
            handle = f.request()["handle"]
            self.assertEqual(f.request(dependencies=["forged"])["rule"], "provenance-handle")
            self.assertEqual(f.request("B", dependencies=[handle])["rule"], "provenance-handle")
            f.runtime.state["handles"][handle]["run"] = "other-run"
            self.assertEqual(f.request(dependencies=[handle])["rule"], "provenance-handle")
            self.assertEqual(f.request(derived_from=[1])["rule"], "request-shape")

    def test_bus_scope_receipt_and_sensitivity(self):
        with Fixture() as f:
            p = dict(recipient="B", topic="results", payload="public collaboration")
            out = f.request(kind="bus_publish", params=p)
            self.assertTrue(out["allow"])
            self.assertEqual(f.runtime.receive(TOKENS["B"], out["handle"])["result"]["data"], p["payload"])
            self.assertEqual(f.runtime.receive(TOKENS["A"], out["handle"])["rule"], "provenance-handle")
            self.assertEqual(f.request(kind="bus_publish", params=dict(p, recipient="C"))["rule"], "bus-scope")
            f.request(params={"path": "secrets/key"})
            self.assertEqual(f.request(kind="bus_publish", params=p)["rule"], "taint-egress")

    def test_no_execution_of_python_or_unknown_endpoints(self):
        with Fixture() as f:
            self.assertEqual(f.request(kind="tool_exec", params={"tool": "python"})["rule"], "execution-disabled")
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "other", "payload": "x"})["rule"], "endpoint-scope")
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "result", "payload": "x", "port": 9999})["rule"], "request-shape")
            self.assertEqual(f.http.received, [])
            f.runtime.endpoint_grants["A"] = frozenset({"result"})
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "redirect", "payload": "x"})["rule"], "endpoint-capability")

    def test_paths_traversal_prefix_symlink_hardlink_and_fifo(self):
        with Fixture() as f:
            for path in ("/work/input/public", "work/../secrets/key", "work-other/public"):
                self.assertFalse(f.request(params={"path": path})["allow"])
            (f.root / "work/input/link").symlink_to(f.root / "secrets/key")
            self.assertFalse(f.request(params={"path": "work/input/link"})["allow"])
            f.restart()  # Adapter error is uncertain and quarantines; explicit review required.
            f.runtime.resume(TOKENS["Z"], "reviewed fixture error", f.incident())
            os.link(f.root / "secrets/key", f.root / "work/input/hardlink")
            self.assertFalse(f.request(params={"path": "work/input/hardlink"})["allow"])
            f.runtime.resume(TOKENS["Z"], "reviewed hardlink denial", f.incident())
            os.mkfifo(f.root / "work/input/fifo")
            self.assertFalse(f.request(params={"path": "work/input/fifo"})["allow"])

    def test_create_only_write_does_not_truncate_existing_file(self):
        with Fixture() as f:
            p = dict(path="work/tmp/output", payload="first")
            self.assertTrue(f.request(kind="file_write", params=p)["allow"])
            self.assertFalse(f.request(kind="file_write", params=dict(p, payload="second"))["allow"])
            self.assertEqual((f.root / "work/tmp/output").read_text(), "first")

    def test_redirect_not_followed_and_address_validation(self):
        with Fixture() as f:
            out = f.request(kind="net_send", params={"endpoint": "redirect", "payload": "x"})
            self.assertEqual(out["rule"], "redirect-disabled")
            self.assertEqual(f.http.received, [b"x"])
        with Fixture() as f:
            f.endpoints["result"] = Endpoint("127.0.0.1", f.http.server_port,
                                            allowed_ips=("192.0.2.1",), response_sensitive=False)
            f.runtime.adapters.endpoints["result"] = f.endpoints["result"]
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "result", "payload": "x"})["rule"], "resolved-address")
            self.assertEqual(f.http.received, [])

    def test_concurrent_aggregate_budget_and_idempotency(self):
        with Fixture(swarm_bytes=9000) as f:
            f.runtime.adapters.perform = lambda *_: {"wire_bytes": 1}
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                outputs = list(pool.map(lambda i: f.request(("A", "B", "C")[i % 3], "net_send",
                                      {"endpoint": "result", "payload": "x"}, rid=str(i)), range(12)))
            self.assertEqual(sum(o["allow"] for o in outputs), 2)
            self.assertLessEqual(f.runtime.broker.monitor._swarm.bytes_out, 9000)
            f.restart()
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "result", "payload": "x"})["rule"], "budget-swarm")

    def test_duplicate_and_conflicting_requests_do_not_repeat_effect(self):
        with Fixture() as f:
            count = []
            f.runtime.adapters.perform = lambda *_: count.append(1) or {"wire_bytes": 1}
            body = dict(request_id="same", type="net_send", params={"endpoint": "result", "payload": "x"})
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                out = list(pool.map(lambda _: f.runtime.execute(TOKENS["A"], body), range(8)))
            self.assertEqual(len(count), 1)
            self.assertTrue(any(x.get("replay") for x in out))
            f.restart()
            self.assertTrue(f.runtime.execute(TOKENS["A"], body)["replay"])
            body["params"]["payload"] = "changed"
            self.assertEqual(f.runtime.execute(TOKENS["A"], body)["rule"], "idempotency-conflict")

    def test_sensitive_read_reserves_taint_before_slow_effect(self):
        with Fixture() as f:
            started, release = threading.Event(), threading.Event()
            perform = f.runtime.adapters.perform
            def delayed(kind, p):
                started.set()
                self.assertTrue(release.wait(3))
                return perform(kind, p)
            f.runtime.adapters.perform = delayed
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                read = pool.submit(f.request, params={"path": "secrets/key"})
                self.assertTrue(started.wait(3))
                denied = f.request(kind="net_send", params={"endpoint": "result", "payload": "x"})
                self.assertEqual(denied["rule"], "taint-egress")
                release.set()
                self.assertTrue(read.result()["allow"])
            self.assertEqual(f.http.received, [])

    def test_storage_failure_before_effect_and_after_effect(self):
        with Fixture() as f:
            def broken(*_):
                raise OSError("fixture storage unavailable")
            f.runtime.store.commit = broken
            out = f.request(kind="file_write", params={"path": "work/tmp/x", "payload": "x"})
            self.assertEqual(out["rule"], "storage-unavailable")
            self.assertFalse((f.root / "work/tmp/x").exists())
            self.assertFalse(f.runtime.healthy)
        with Fixture() as f:
            original = f.runtime.store.commit
            calls = []
            def fail_completion(*args):
                calls.append(1)
                if len(calls) == 2:
                    raise OSError("completion unavailable")
                return original(*args)
            f.runtime.store.commit = fail_completion
            out = f.request(kind="file_write", params={"path": "work/tmp/x", "payload": "x"}, rid="write")
            self.assertEqual(out["status"], "uncertain")
            self.assertTrue((f.root / "work/tmp/x").exists())
            f.restart()
            self.assertTrue(f.runtime.broker.monitor.quarantined)

    def test_crash_pending_reconciliation_no_replay(self):
        class Crash(BaseException):
            pass
        with Fixture() as f:
            def crash(*_):
                raise Crash()
            f.runtime.adapters.perform = crash
            with self.assertRaises(Crash):
                f.request(kind="file_write", params={"path": "work/tmp/x", "payload": "x"}, rid="crash")
            f.restart()
            self.assertTrue(f.runtime.broker.monitor.quarantined)
            replay = f.request(kind="file_write", params={"path": "work/tmp/x", "payload": "x"}, rid="crash")
            self.assertEqual(replay["status"], "uncertain")
            self.assertTrue(replay["replay"])
            self.assertFalse((f.root / "work/tmp/x").exists())

    def test_resume_authenticated_preserves_taint_budgets_and_audit(self):
        with Fixture() as f:
            f.request(params={"path": "secrets/key"})
            f.request(kind="net_send", params={"endpoint": "result", "payload": "x"})
            incident = f.incident()
            count = f.runtime.broker.monitor._swarm.requests
            self.assertEqual(f.runtime.resume(TOKENS["A"], "reason", incident)["rule"], "admin-role-required")
            self.assertEqual(f.runtime.resume(TOKENS["Z"], "", incident)["rule"], "review-required")
            self.assertTrue(f.runtime.resume(TOKENS["Z"], "reviewed fixture incident", incident)["allow"])
            self.assertEqual(f.runtime.broker.monitor._swarm.requests, count)
            f.restart()
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "result", "payload": "x"})["rule"], "taint-egress")
            self.assertEqual(f.http.received, [])

    def test_audit_redaction_checkpoints_and_single_writer(self):
        with Fixture() as f:
            f.request(params={"path": "secrets/key"})
            checkpoint = f.runtime.checkpoint(TOKENS["Z"])
            f.runtime.store.verify_checkpoint(checkpoint, AUDIT_KEY)
            for body, in f.runtime.store.db.execute("SELECT body FROM audit"):
                self.assertNotIn("fixture-sensitive-value", body)
                self.assertNotIn(TOKENS["A"], body)
            state = json.dumps(f.runtime.store.load())
            self.assertNotIn("fixture-sensitive-value", state)
            with self.assertRaises(BlockingIOError):
                Store(str(f.base / "state.sqlite"))
            with self.assertRaises(ValueError):
                f.runtime.store.verify_checkpoint(dict(checkpoint, signature="0" * 64), AUDIT_KEY)
            f.runtime.store.db.execute("DELETE FROM audit WHERE seq=?", (checkpoint["seq"],))
            with self.assertRaises(ValueError):
                f.runtime.store.verify_checkpoint(checkpoint, AUDIT_KEY)

    def test_benign_cooperation_review_signals_and_workflow_permissions(self):
        for workflows in (frozenset(), frozenset({"127.0.0.1"})):
            with Fixture(workflows=workflows) as f:
                f.runtime.adapters.perform = lambda *_: {"wire_bytes": 1}
                self.assertTrue(f.request(kind="dns_resolve", params={"endpoint": "result"})["allow"])
                for agent in ("B", "A", "C"):
                    self.assertTrue(f.request(agent, "net_send", {"endpoint": "result", "payload": "public"})["allow"])
                self.assertEqual(bool(f.runtime.broker.monitor.review_signals), not bool(workflows))

    def test_abstract_boundary_and_exact_dns(self):
        from test_sentinel import _broker
        b = _broker()
        self.assertEqual(b.submit(Action("A", ActionType.DNS_RESOLVE, {"host": "data.ok.host"})).rule, "dns-allowlist")
        self.assertFalse(b.audit[-1].decision.allow)
        for path in ("/work-other/x", "/work/../secrets/key"):
            self.assertFalse(b.submit(Action("A", ActionType.FILE_READ, {"path": path})).allow)
        action = Action("A", ActionType.FILE_READ, {"path": "/work/x"})
        decision = b.submit(action)
        action.params["path"] = "/changed"
        decision.rule = "changed"
        self.assertTrue(b.audit.verify())

    def test_unix_http_auth_and_request_limits(self):
        import http.client
        import socket
        with Fixture() as f:
            path = str(f.base / "service.sock")
            server = UnixServer(path, Handler)
            server.runtime = f.runtime
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def post(auth):
                connection = http.client.HTTPConnection("localhost", timeout=3)
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.connect(path)
                body = json.dumps(dict(request_id="http", type="file_read", params={"path": "work/input/public"}))
                connection.request("POST", "/execute", body, {"Authorization": auth})
                response = json.loads(connection.getresponse().read())
                connection.close()
                return response
            try:
                self.assertEqual(post("Bearer invalid")["rule"], "authentication")
                self.assertTrue(post("Bearer " + TOKENS["A"])["allow"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_pending_operations_block_resume_and_new_work_after_quarantine(self):
        with Fixture() as f:
            started, release = threading.Event(), threading.Event()
            def delayed(*_):
                started.set()
                self.assertTrue(release.wait(3))
                return {"wire_bytes": 1}
            f.runtime.adapters.perform = delayed
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                active = pool.submit(f.request, kind="net_send", params={"endpoint": "result", "payload": "public"})
                self.assertTrue(started.wait(3))
                self.assertEqual(f.request("B", params={"path": "secrets/canary"})["rule"], "canary-tripwire")
                incident = f.incident()
                self.assertEqual(f.runtime.resume(TOKENS["Z"], "review", incident)["rule"], "operations-pending")
                self.assertEqual(f.request("C")["rule"], "swarm-quarantined")
                release.set()
                self.assertTrue(active.result()["allow"])

    def test_timeouts_and_partial_effects_remain_charged(self):
        with Fixture() as f:
            def timeout(*_):
                f.http.received.append(b"partial")
                raise TimeoutError("fixture partial send")
            f.runtime.adapters.perform = timeout
            out = f.request(kind="net_send", params={"endpoint": "result", "payload": "payload"}, rid="partial")
            self.assertEqual(out["status"], "uncertain")
            reserved = f.runtime.broker.monitor._swarm.bytes_out
            self.assertGreater(reserved, len("payload"))
            f.restart()
            self.assertEqual(f.runtime.broker.monitor._swarm.bytes_out, reserved)
            replay = f.request(kind="net_send", params={"endpoint": "result", "payload": "payload"}, rid="partial")
            self.assertTrue(replay["replay"])
            self.assertEqual(f.http.received, [b"partial"])

    def test_correlation_window_expires(self):
        with Fixture() as f:
            f.runtime.adapters.perform = lambda *_: {"wire_bytes": 1}
            f.request(kind="dns_resolve", params={"endpoint": "result"})
            f.runtime.broker.monitor._activity = [(time.time() - 400, "dns_resolve", "127.0.0.1", "A")]
            self.assertTrue(f.request("B", "net_send", {"endpoint": "result", "payload": "public"})["allow"])
            self.assertEqual(f.runtime.broker.monitor.review_signals, [])

    def test_sensitive_http_response_taints_context(self):
        with Fixture() as f:
            from dataclasses import replace
            f.runtime.adapters.endpoints["result"] = replace(f.endpoints["result"], response_sensitive=True)
            self.assertTrue(f.request(kind="net_send", params={"endpoint": "result", "payload": "public"})["allow"])
            self.assertEqual(f.request(kind="net_send", params={"endpoint": "result", "payload": "copied"})["rule"], "taint-egress")
            self.assertEqual(f.http.received, [b"public"])

    def test_tls_service_and_verified_pinned_https_adapter(self):
        import http.client
        import shutil
        import ssl
        import subprocess
        if not shutil.which("openssl"):
            self.skipTest("openssl required for local TLS fixture")
        with Fixture() as f:
            cert, key = str(f.base / "cert.pem"), str(f.base / "key.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                "-keyout", key, "-out", cert], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server = TLSServer(("127.0.0.1", 0), Handler)
            server.context, server.runtime = context, f.runtime
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps(dict(request_id="tls", type="file_read", params={"path": "work/input/public"}))
                client = http.client.HTTPSConnection("127.0.0.1", server.server_port,
                                                    context=ssl.create_default_context(cafile=cert), timeout=3)
                client.request("POST", "/execute", body, {"Authorization": "Bearer " + TOKENS["A"]})
                self.assertTrue(json.loads(client.getresponse().read())["allow"])
                client.close()
                untrusted = http.client.HTTPSConnection("127.0.0.1", server.server_port, timeout=3)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    untrusted.request("POST", "/execute", body)
                untrusted.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
            https = TLSServer(("127.0.0.1", 0), LocalService)
            https.context, https.received = context, []
            thread = threading.Thread(target=https.serve_forever, daemon=True)
            thread.start()
            try:
                f.runtime.adapters.endpoints["result"] = Endpoint("127.0.0.1", https.server_port,
                    allowed_ips=("127.0.0.1",), response_sensitive=False, ca_file=cert)
                out = f.request(kind="net_send", params={"endpoint": "result", "payload": "verified"})
                self.assertTrue(out["allow"])
                self.assertEqual(out["result"]["data"], "accepted:verified")
            finally:
                https.shutdown()
                https.server_close()
                thread.join()

    def test_config_loader_requires_private_directories_and_policy_match(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent) / "private"
            subprocess.run([sys.executable, "deploy/init-execution.py", str(base)], check=True, capture_output=True)
            runtime = load_runtime(str(base / "config.json"))
            runtime.close()
            os.chmod(base / "workspace", 0o755)
            with self.assertRaises(ValueError):
                load_runtime(str(base / "config.json"))
        with Fixture() as f:
            f.runtime.close()
            f.runtime = None
            store = Store(str(f.base / "state.sqlite"))
            adapter = Adapters(str(f.root), f.endpoints)
            try:
                with self.assertRaises(ValueError):
                    Runtime(f.policy, adapter, store, f.credentials, **dict(f.kw, policy_version="changed"))
            finally:
                store.close()
                adapter.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
