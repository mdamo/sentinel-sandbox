"""
HTTP front end for the broker, used by the host-side microVM deployment.

Stdlib only (no external deps) so the sentinel stays small and auditable.
Agents POST a JSON action to /submit; the sentinel returns {"allow": bool, ...}.
In this PoC the sentinel still does not perform the real effect — it returns the
decision. A production sentinel would, on allow, carry out the effect itself via
a trusted adapter so the agent never holds an outbound socket.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sentinel import Broker, Budget, Capability, Monitor, Policy, ResponsePolicy
from sentinel.actions import Action, ActionType
from sentinel.response import Alert
from swarm.catalog import AGENT_ROLES, TOOL_BINARIES


def default_broker() -> Broker:
    policy = Policy(sensitive_prefixes=("/secrets/",),
                    canary_paths=frozenset({"/secrets/.honeytoken"}))
    cap = Capability(
        allowed_types=frozenset(ActionType),
        net_allowlist=frozenset({"api.internal.svc"}),
        tool_allowlist=TOOL_BINARIES,
        read_prefixes=("/work/", "/secrets/"),
        write_prefixes=("/work/tmp/",),
    )
    for a in AGENT_ROLES:
        policy.grant(a, cap)
    monitor = Monitor(
        Budget(5000, 20, 2), Budget(50000, 100, 3),
        response=ResponsePolicy.strict(),
        on_alert=lambda a: print(f"[sentinel | host | alert] {a.line()}", flush=True),
    )
    return Broker(policy, monitor)


BROKER = default_broker()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/submit":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            action = Action(
                agent_id=body["agent_id"],
                type=ActionType(body["type"]),
                params=body.get("params", {}),
                derived_from=body.get("derived_from", []),
            )
            decision = BROKER.submit(action)
            out = {"allow": decision.allow, "rule": decision.rule,
                   "reason": decision.reason}
            print(f"[sentinel | host | decision] peer={self.client_address[0]} "
                  f"{BROKER.audit[-1].line()}", flush=True)
        except Exception as exc:  # fail closed
            out = {"allow": False, "rule": "fail-closed", "reason": repr(exc)}
            print(f"[sentinel | host | decision] peer={self.client_address[0]} "
                  "DENY rule=fail-closed", flush=True)
        payload = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        pass  # audit line is printed above instead


def main() -> None:
    host, _, port = os.environ.get("SENTINEL_BIND", "0.0.0.0:8085").partition(":")
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    print(f"[sentinel | host] ready endpoint=http://{host}:{port}/submit "
          f"pid={os.getpid()}; evaluates agent actions on the host", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
