# Repeating the six-role HTTP demo

Provision a signing key per roster agent and an effect root, then start the
sentinel in one terminal:

```bash
umask 077
python3 -c 'import json,secrets; print(json.dumps({f"agent-{i}": secrets.token_hex(32) for i in range(1, 7)}))' > /tmp/keys.json
mkdir -p /tmp/effects/work/input && printf '%s\n' '{"task":"result ok"}' > /tmp/effects/work/input/task.json
SENTINEL_BIND=127.0.0.1:8085 SENTINEL_KEYS_FILE=/tmp/keys.json \
  SENTINEL_EFFECT_ROOT=/tmp/effects python3 -m sentinel.serve
```

Run the client in another terminal, from `sentinel-poc`:

```bash
BROKER_URL=http://127.0.0.1:8085/submit AGENT_KEYS_FILE=/tmp/keys.json \
  python3 -m swarm.agent_client
```

Each invocation submits eight actions across six roles, each signing as itself,
and expects six allows, one `egress-allowlist` denial, and one `capability-type`
denial of `tool_exec`. Allowed actions run through the host effect adapter, which
performs confined file effects and local outbox/bus records; it runs no
agent-supplied program. All six roles run sequentially in the same client
process.

The server retains state across client invocations. Previously, the resolver's
DNS action in one run caused the researcher's send in the next run to trigger
`corr-split-role`. Strict response then blocked that agent for the server's
lifetime. Changing action order only avoided the failure on the first run.

The HTTP demo server now configures `api.internal.svc` as an expected shared
workflow using the monitor's existing `workflow_hosts` setting. That exact host
is exempt from split-role and split-payload heuristics. Capabilities, budgets,
taint, canaries, agent blocks, quarantine and audit remain active. Other hosts
retain correlation checks, and the attack demos retain their existing rules.

After updating, stop the old abstract server with Ctrl-C and start it again with
the command above. Restarting the client alone cannot load the server change or
clear an agent block. Restart discards this abstract server's in-memory state
and audit; this is not a recovery procedure for the durable execution service.

With no other traffic, ten complete client invocations fit the default budgets.
The eleventh hits `budget-agent` because agent-1 has already used its twenty
allowed requests. Limits deliberately accumulate; the client does not reset
them. Start a fresh abstract demo server when you need a new budget.

Run `python3 test_http_client.py` to verify two independent client processes
against one server, cumulative budget enforcement, taint/quarantine, and
correlation on another host. The tests use loopback and require no live provider.
