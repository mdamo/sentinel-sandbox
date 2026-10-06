# Repeating the six-role HTTP demo

Start the abstract sentinel in one terminal:

```bash
SENTINEL_BIND=127.0.0.1:8085 python3 -m sentinel.serve
```

Run the client in another terminal, from `sentinel-poc`:

```bash
BROKER_URL=http://127.0.0.1:8085/submit python3 -m swarm.agent_client
```

Each invocation submits eight abstract actions across six roles, expecting seven
allows and one `egress-allowlist` denial. No proposed effects are executed.
All six roles run sequentially in the same client process.

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
