"""
HTTP front end for the broker, used by the host-side microVM deployment.

Stdlib only (no external deps) so the sentinel stays small and auditable.
Agents sign each request with a per-agent key. The authenticated identity is
bound to the action; approved actions run through the host-owned adapter.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sentinel import Broker, Budget, Capability, Monitor, Policy, ResponsePolicy
from sentinel.actions import Action, ActionType
from sentinel.effects import EffectAdapter
from sentinel.identity import IdentityError, IdentityStore
from sentinel.response import Alert
from swarm.catalog import AGENT_ROLES, TOOL_BINARIES


def default_broker() -> Broker:
    policy = Policy(sensitive_prefixes=("/secrets/",),
                    canary_paths=frozenset({"/secrets/.honeytoken"}))
    cap = Capability(
        allowed_types=frozenset(set(ActionType) - {ActionType.TOOL_EXEC}),
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


class SentinelHTTPServer(ThreadingHTTPServer):
    def __init__(self, address, broker: Broker, identities: IdentityStore,
                 effects: EffectAdapter):
        super().__init__(address, Handler)
        self.broker = broker
        self.identities = identities
        self.effects = effects


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/submit":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 1 or length > 65536:
                raise ValueError("invalid request size")
            raw = self.rfile.read(length)
            server: SentinelHTTPServer = self.server  # type: ignore[assignment]
            identity = server.identities.authenticate(
                self.headers.get("X-Agent-ID", ""),
                self.headers.get("X-Nonce", ""), raw,
                self.headers.get("X-Signature", ""))
            body = json.loads(raw)
            if "agent_id" in body and body["agent_id"] != identity:
                raise IdentityError("body identity does not match credential")
            action = Action(
                agent_id=identity,
                type=ActionType(body["type"]),
                params=body.get("params", {}),
                derived_from=body.get("derived_from", []),
            )
            decision, result = server.broker.execute(action, server.effects.perform)
            out = {"allow": decision.allow, "rule": decision.rule,
                   "reason": decision.reason}
            if decision.allow:
                out["result"] = result
            print(f"[sentinel | host | decision] peer={self.client_address[0]} "
                  f"{server.broker.audit[-1].line()}", flush=True)
        except IdentityError as exc:
            out = {"allow": False, "rule": "identity-auth", "reason": str(exc)}
        except Exception as exc:  # fail closed
            out = {"allow": False, "rule": "fail-closed", "reason": type(exc).__name__}
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
    keys = os.environ["SENTINEL_KEYS_FILE"]
    effect_root = os.environ["SENTINEL_EFFECT_ROOT"]
    srv = SentinelHTTPServer((host, int(port)), default_broker(),
                             IdentityStore.from_file(keys), EffectAdapter(effect_root))
    print(f"[sentinel | host] ready endpoint=http://{host}:{port}/submit "
          f"pid={os.getpid()}; evaluates agent actions on the host", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
