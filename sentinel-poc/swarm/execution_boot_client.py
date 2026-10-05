"""Authenticated microVM fixture: real workspace effects and direct-access checks."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import uuid


def main():
    token = Path("/app/execution.token").read_text().strip()
    boot = json.loads(Path("/app/execution-boot.json").read_text())
    context = ssl.create_default_context(cafile="/app/execution-ca.pem")
    run = uuid.uuid4().hex
    def request(kind, params, auth=token):
        connection = http.client.HTTPSConnection("172.16.0.1", 8085, context=context, timeout=10)
        try:
            body = json.dumps(dict(request_id=run + "-" + uuid.uuid4().hex, type=kind, params=params))
            connection.request("POST", "/execute", body,
                               {"Authorization": "Bearer " + auth, "Content-Type": "application/json"})
            return json.loads(connection.getresponse().read(262144))
        finally:
            connection.close()
    denied = request("file_write", {"path": "output/denied-" + run, "payload": "fixture"}, "invalid")
    assert not denied["allow"] and denied["rule"] == "authentication", denied
    read = request("file_read", {"path": "input/task.txt"})
    assert read["allow"] and read["result"]["data"] == "public task\n", read
    written = request("file_write", {"path": "output/boot-" + run + ".txt", "payload": "public task completed"})
    assert written["allow"] and written["result"]["bytes"] == len("public task completed"), written
    forbidden = request("net_send", {"endpoint": "unapproved", "payload": "fixture"})
    assert not forbidden["allow"] and forbidden["rule"] in {"endpoint-scope", "capability-type"}, forbidden
    for host, port in (("172.16.0.1", 8086), ("192.0.2.1", 443)):
        try:
            with socket.create_connection((host, port), timeout=1):
                raise AssertionError("unexpected direct network access")
        except OSError:
            pass
    protected = Path(boot["host_workspace"]) / "input/task.txt"
    try:
        protected.read_bytes()
    except OSError:
        pass
    else:
        raise AssertionError("host workspace visible directly in guest")
    print("SENTINEL_EXECUTION_BOOT_PASS authentication adapters direct-access-denied", flush=True)


if __name__ == "__main__":
    main()
