# Deterministic Sentinel — AI-swarm containment PoC
Repo that creates a deterministic sentinel for probabilistic AI swarms.

A proof of concept for the idea: **put a guard on the sandbox.** Today most
agent sandboxes are a wall with no sentinel. Here the agents run in a
Firecracker microVM (the "cell") and a separate, trusted **sentinel** is the single door
every action must pass through. The sentinel's decisions are **deterministic** —
no LLM, no persuasion, same input → same decision, every decision explained by
the name of the rule that fired.

The design follows the lesson from the July 2026 OpenAI eval escape, where
models broke out through the *one permitted egress channel* (a package-registry
proxy with an SSRF gap): an allowlist is necessary but not sufficient. So the
sentinel adds stateful, swarm-aware checks on top of the allowlist.

The repository includes abstract demos plus an opt-in trusted execution service:

- **Local demo:** six scripted agents and abstract attack scenarios run in one
  Python process. No microVM or live model is started.
- **Live NVIDIA Nemotron demo:** six agents request model proposals from NVIDIA,
  then submit abstract tool calls to the local deterministic sentinel.
- **Local HTTP smoke test:** six separate agent identities sign action records
  and submit them to the sentinel service, which performs confined host effects.
- **Firecracker deployment:** an unprivileged guest client submits signed records
  to a sentinel on the Linux/KVM host through a restricted TAP interface.
- **Trusted execution service:** authenticated callers request real workspace
  reads, create-only writes, scoped HTTP/DNS operations, and messages. SQLite
  persists budgets, sensitivity, audit, idempotency, and quarantine. See the
  [Linux execution guide](EXECUTION_GUIDE.md) for setup and recovery.

> **Safety note.** The local demo performs no effects. The HTTP service uses a
> host-owned adapter for confined file reads/writes and local outbox/bus records.
> It opens no outbound socket and executes no agent-supplied program. The opt-in
> execution service performs narrowly scoped real effects; its tests use
> temporary files and local services. The live demo makes real HTTPS requests to
> NVIDIA for model proposals. The microVM launcher configures a local
> TAP/firewall. Attack scenarios remain abstract action records, not working
> attack code.

## Architecture

```mermaid
flowchart LR
    subgraph Guest["Firecracker microVM — untrusted cell"]
        Agent["Agent client<br/>read-only guest rootfs<br/>172.16.0.2"]
    end
    subgraph Host["Linux/KVM host — trusted side"]
        TAP["TAP link<br/>172.16.0.1 ↔ 172.16.0.2"]
        FW["nftables<br/>only port 8085 allowed"]
        API["Authenticated sentinel HTTP service"]
        Broker["Broker"]
        Policy["Stateless policy"]
        Monitor["Stateful monitor"]
        Effects["Host effect adapter"]
        Audit["In-memory hash-chained audit"]
        Logs["stdout: decisions and alerts"]
    end
    Agent -- "POST structured Action" --> TAP --> FW --> API --> Broker
    Broker --> Policy --> Monitor --> Broker
    Broker --> Audit --> Logs
    Broker --> Effects
    Broker -- "allow / deny + rule" --> API --> Agent
```

The guest has one network interface and no default route. The host firewall
drops guest traffic except requests to the sentinel. The HTTP service verifies
a per-agent HMAC signature and one-time nonce before binding the identity to
the action. The broker applies policy and stateful checks, then invokes the host
adapter only on an allow. The adapter performs confined file effects, records
allowed sends and bus messages locally, and returns a fixed DNS result. Live
tool execution is denied. The separate execution service performs approved
effects through its own trusted adapters and likewise rejects arbitrary
Python/shell execution.

The sentinel prints audited decisions and escalation alerts to stdout. The
audit chain lives in memory and is lost when the process exits. The boot test
captures host and guest console output in a temporary file, prints it on
failure, and deletes it on exit. Execution mode instead persists redacted audit
and security state in SQLite with signed checkpoints for independent retention.

## Layers

| Layer | File | Job |
|---|---|---|
| Action vocabulary | `sentinel/actions.py` | Agents touch the world only via typed `Action`s (a finite action calculus). No raw sockets/files/subprocess. |
| Deterministic policy | `sentinel/policy.py` | Allow/deny of a single action in isolation. Default-deny, per-agent capabilities, exact-host allowlists, canary paths. Outside the model. |
| Stateful monitor | `sentinel/monitor.py` | What the policy can't see: cumulative **budgets** (per-agent **and** per-swarm), **taint** tracking, **provenance**, **swarm correlation**. A sensitive read also leaves persistent taint on that agent, so omitting `derived_from` does not clear it. Can only make a decision *stricter*. Fails closed. |
| Broker | `sentinel/broker.py` | The single enforcement point. Complete mediation: policy → monitor → allow/deny, with fail-closed handling and an audit log. |
| Response policy | `sentinel/response.py` | Maps denied rules to deny-only, agent blocking, or swarm quarantine; emits escalation alerts. |
| Agent interface | `swarm/ai_agents.py`, `swarm/catalog.py` | Six agent roles, a scripted model backend, and six tools that submit abstract actions. |
| Live model backend | `swarm/nemotron.py`, `swarm/live_demo.py` | NVIDIA Nemotron proposes calls; the local sentinel decides permission. |
| HTTP front end | `sentinel/serve.py` | Same broker as a stdlib HTTP service on the Linux host. |
| Identity | `sentinel/identity.py` | Per-agent HMAC authentication with replay checks. |
| Effects | `sentinel/effects.py` | Host-owned confined file effects and local send/bus records. |
| Execution boundary | `sentinel/runtime.py`, `sentinel/adapters.py` | Authenticated effects, sticky sensitivity, handles, reservations, and idempotency. |
| Durable state | `sentinel/storage.py` | Single-writer SQLite, audit chain, signed state/checkpoints. |
| Authenticated API | `sentinel/execution_service.py` | Protected Unix socket or TLS, separate agent/admin endpoints. |

## What it catches (and how)

| Pattern | Check | Rule that fires |
|---|---|---|
| Send secret straight out | destination allowlist | `egress-allowlist` |
| Abuse the one *permitted* host | cumulative outbound budgets | `budget-agent` / `budget-swarm` |
| read → transform → send to an **allowlisted** host | inherited taint through provenance | `taint-egress` |
| Smuggle bytes in DNS names | covert channel | `dns-allowlist` |
| Agent A probes, agent B sends | multi-agent split role | `corr-split-role` |
| N agents each send a slice | distributed exfiltration / collusion | `corr-split-payload` |
| Touch a honeytoken | canary tripwire | `canary-tripwire` (hard kill) |

## What happens on detection

Detection and *response* are separated so the reaction is a reviewed setting
(`sentinel/response.py`), not hard-coded. A deny always blocks the action first;
on top of that, a `ResponsePolicy` maps the rule that fired to an escalation:

| Mode | Effect |
|---|---|
| `DENY_ONLY` | block this action; the agent keeps operating |
| `KILL_AGENT` | block + permanently deny every future action from this agent |
| `QUARANTINE_SWARM` | block + deny future broker actions from every agent (`swarm-quarantined`) |

Any escalation also emits an `Alert` to an out-of-band sink (a human/SIEM) — in
the demo it prints `!! ALERT [...]`. Two presets: `ResponsePolicy.preserve_original()`
(taint/canary kill the agent) and `ResponsePolicy.strict()` (a confirmed leak
quarantines on taint, canary, and split-payload detections; split-role kills the
sending agent). The local demo uses the original preset, then demonstrates the
strict preset separately. The HTTP service uses the strict preset.

These responses change broker state; they do not terminate processes or stop
the VM. Abstract mode has no review/resume endpoint. Execution mode provides
authenticated incident recovery while retaining budgets and sensitivity.

The audit log is **hash-chained** (`AuditLog`): each entry commits selected
action and decision fields to the previous hash. `audit.verify()` detects
changes to those committed fields. It is in memory only; durable, out-of-band
storage is used in execution mode. Independently retain signed checkpoints;
automatic remote checkpoint shipping is not implemented.

## Quick start

Use Python 3.13. The demo and direct test runner need no third-party packages,
API credentials, root privileges, or KVM. Run from the repository root:

```bash
cd sentinel-poc
python3.13 run_demo.py        # swarm demo + response-on-detection + chain verify
python3.13 test_sentinel.py   # 23 tests  (or: pytest)
python3.13 test_http_client.py # 4 HTTP demo regression tests
```

The demo should finish with `ALL SCENARIOS BEHAVED AS EXPECTED`,
`total actions: 13   denied: 6`, and a successful audit-chain verification.
The direct test runner should report `23/23 tests passed`, and
`test_http_client.py` should report `OK`. Split-payload and strict-response
examples use separate brokers from the 13-action summary.

### Live NVIDIA Nemotron demo

Create `.env` in the repository root (beside this README) with your NVIDIA API
key. The live backend automatically loads it, regardless of the working directory:

```dotenv
NVIDIA_API_KEY=your-nvidia-api-key
NVIDIA_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
LOG_LEVEL=INFO
```

| Setting | Behavior |
|---|---|
| `NVIDIA_API_KEY` | Required for the live demo. |
| `NVIDIA_MODEL` | Defaults to `nvidia/nemotron-3.5-lightning-30b-a3b`; must start with `nvidia/nemotron-`. |
| `NVIDIA_BASE_URL` | Defaults to `https://integrate.api.nvidia.com/v1`; must use HTTPS. The backend appends `/chat/completions`. |
| `LOG_LEVEL` | Defaults to `INFO`; accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |

The default is [Nemotron 3.5 Lightning 30B A3B](https://build.nvidia.com/nvidia/nemotron-3.5-lightning-30b-a3b/build).
The earlier `nvidia/nemotron-nano-3-30b-a3b` setting returned HTTP 404.
The corrected older ID, `nvidia/nemotron-3-nano-30b-a3b`, returns HTTP 410;
NVIDIA reports that it reached end of life on September 1, 2026.

Existing shell environment variables take precedence over `.env`. The file is
ignored by Git, and the key is used only by the model transport.

Run from the repository root:

```bash
cd sentinel-poc
python3.13 -m swarm.live_demo
```

To supply a task or override the configured model:

```bash
python3.13 -m swarm.live_demo \
  --model nvidia/nemotron-3.5-lightning-30b-a3b \
  --task "Produce a short result for the sandbox demo"
```

The demo makes one NVIDIA request per role and validates all six proposals before
submitting any tool calls. Each proposal contains one to six calls. The sentinel
then prints an `ALLOW` or `DENY` decision and rule for each abstract action,
followed by action counts and `audit chain verifies: True` on success.

Requests use JSON response mode, disable thinking, and cap output at 2048 tokens.
The prompt assigns a tool to each role and specifies empty arguments for
`run_python`; generated proposals still undergo strict local validation.
Requests have a 60-second timeout, with no retries or provider fallback. Missing
credentials, request failures, or invalid proposals stop the demo with exit code 1
before any tool calls are submitted. The live demo runs in a local Python process;
the Firecracker client continues to use its three-action smoke test.

Verification on October 3, 2026: all 19 offline tests and the local demo
passed. The replacement accepted live requests, but checks encountered an
incomplete response, malformed JSON, and provider timeouts. The final live
run timed out before submitting actions; a successful six-agent live run
has not yet been verified.

### Local HTTP smoke test

Create a key map for the six roster agents and an effect root, then start the
sentinel bound to loopback in one terminal:

```bash
cd sentinel-poc
umask 077
python3.13 -c 'import json,secrets; print(json.dumps({f"agent-{i}": secrets.token_hex(32) for i in range(1, 7)}))' > /tmp/keys.json
mkdir -p /tmp/effects/work/input && printf '%s\n' '{"task":"result ok"}' > /tmp/effects/work/input/task.json
SENTINEL_BIND=127.0.0.1:8085 SENTINEL_KEYS_FILE=/tmp/keys.json \
  SENTINEL_EFFECT_ROOT=/tmp/effects python3.13 -m sentinel.serve
```

In another terminal, submit the eight smoke-test actions of the six roles:

```bash
cd sentinel-poc
BROKER_URL=http://127.0.0.1:8085/submit AGENT_KEYS_FILE=/tmp/keys.json \
  python3.13 -m swarm.agent_client
```

Each role signs its own requests. Expect an allowed read, allowed sends to
`api.internal.svc`, an allowed scratch write, an allowed DNS resolve and bus
publish, a denied send to `drop.attacker.example` with rule `egress-allowlist`,
and a denied `tool_exec` with rule `capability-type` — the host adapter runs no
agent-supplied program. Stop the server with Ctrl-C when finished.
`SENTINEL_BIND` defaults to `0.0.0.0:8085`; `BROKER_URL` defaults to the microVM
endpoint `http://172.16.0.1:8085/submit`.

The service accepts JSON at `POST /submit` with `agent_id`, `type`, `params`,
and optional `derived_from` action IDs. It returns `allow`, `rule`, and `reason`.
Malformed action bodies return a deny with `fail-closed`; an unknown endpoint
returns HTTP 404. Valid submissions receive HTTP 200 even when denied, so
clients must inspect `allow`.

## Six AI agents and six tools

The local demo now creates six `AIAgent` instances with distinct roles:
researcher, writer, analyst, reporter, resolver, and coordinator (`agent-1`
through `agent-6`). The HTTP service recognizes the same six identities, but
accepts a request only when its identity has a configured key.

| Tool | Sentinel action |
|---|---|
| `read_file` | `file_read` |
| `write_file` | `file_write` |
| `run_python` | `tool_exec` (python only) |
| `send_result` | `net_send` |
| `resolve_host` | `dns_resolve` |
| `publish_message` | `bus_publish` |

`swarm/ai_agents.py` provides the model interface and tool registry. Every tool
call goes through `Broker.submit`, including provenance supplied in
`ToolCall.derived_from`. The local demo submits abstract intents and executes no
effects. The six tools wrap the existing action vocabulary; only `python` is an
allowed tool binary there. The HTTP service denies `tool_exec`.

The default `OfflineModel` is a scripted simulation, **not a live LLM**. To
integrate a model, implement `propose(role, task) -> list[ToolCall]` and pass
that backend to `build_ai_agents(model)`. The model proposes actions; the
sentinel remains deterministic and retains sole authority to allow or deny.
The optional live backend uses NVIDIA Nemotron for model proposals. The
microVM client runs the six-role mediation smoke test.

## Firecracker microVM deployment

This deployment needs a **Linux host with KVM** and the Firecracker binary. It
cannot boot directly on macOS. Obtain a compatible guest kernel image from the
[Firecracker releases](https://github.com/firecracker-microvm/firecracker/releases)
for the host architecture. On a Debian/Ubuntu Linux host, install `debootstrap`,
`e2fsprogs`, `iproute2`, `nftables`, and `coreutils`, plus Python 3.13 on the host,
then build a Debian Trixie guest image. Create a key map outside the guest image;
the builder embeds the keys of the six roster agents and nothing else. Use the
same map when launching:

```bash
cd sentinel-poc
umask 077
python3.13 -c 'import json,secrets; print(json.dumps({f"agent-{i}": secrets.token_hex(32) for i in range(1, 7)}))' > /path/to/keys.json
sudo SENTINEL_KEYS_FILE=/path/to/keys.json deploy/microvm/build-rootfs.sh /path/to/agent.ext4
sudo SENTINEL_KEYS_FILE=/path/to/keys.json KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 \
  deploy/microvm/run.sh
```

To run the boot integration test on that Linux/KVM host, build a fresh guest
image from the current source, then run:

```bash
cd sentinel-poc
sudo SENTINEL_KEYS_FILE=/path/to/keys.json KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 \
  deploy/microvm/test-boot.sh
```

The test boots the guest, waits up to 120 seconds, and checks that a confined
file read returned content, an allowed send reached the host outbox, and an
external-host send was denied by
`egress-allowlist`. The guest prints `SENTINEL_BOOT_TEST_PASS` only after every
response of all six roles matches. The test exits 77 with `SKIP` on hosts without Linux
KVM. The local Python demo and tests do not verify guest boot or firewall enforcement;
run this integration test separately on the target Linux/KVM host.

The rootfs builder downloads Debian packages. The launcher creates one TAP,
one dedicated nftables table, and a temporary VM config, then removes them on
exit. It refuses to replace an existing TAP or firewall table. Inspect the
scripts before running them as root. The guest rootfs is mounted read-only;
the guest agent runs as UID 10002. For a production deployment, run Firecracker
under its **jailer** with a dedicated unprivileged host user and appropriate
resource limits, following the [Firecracker host guidance](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).

- The guest has one NIC, a static address (`172.16.0.2`), and **no default route**.
- Host firewall rules allow guest traffic only to the sentinel on
  `172.16.0.1:8085`; guest forwarding is denied even if the guest changes routes.
- The sentinel runs on the Linux host, outside the guest, and has no third-party
  Python dependencies. Approved file actions touch only its configured effect
  root. Allowed sends and bus publishes append local records; they do not
  deliver packets or messages to external services. Optional execution mode
  uses TLS and runs the service under a dedicated non-root identity; see
  [the execution guide](EXECUTION_GUIDE.md).

## Honest limits (what a reviewer will ask)

1. **The microVM launcher is a PoC, not a hardened host setup.** Firecracker
   provides a guest kernel boundary, but the launcher does not use the Firecracker
   jailer or set host resource limits. The host kernel, KVM, and firewall remain
   part of the trust boundary. The sentinel is outside the guest.
2. **Deterministic means it only catches what you specified.** The correlation
   rules here (split-role, split-payload) are illustrative; a real deployment
   needs a tuned, reviewed catalogue and will still miss novel patterns. The
   intended design pairs this deterministic enforcer (final authority) with an
   optional LLM analyzer that sits **off the critical path** and may only
   *propose stricter* rules or flag for a human — never loosen policy.
3. **Agent-history taint closes one omission path, but is conservative.** Once an
   agent reads a sensitive path, its later network, DNS, and bus actions are
   denied even if it omits `derived_from`. This may block legitimate clean
   outbound work by that agent. Cross-agent data flow still depends on declared
   provenance; execution mode validates opaque handles and conservatively labels
   contexts and files, but sensitive inputs arriving through other channels still
   need trusted classification. The HTTP front end now authenticates requests
   with per-agent keys. The local demo still uses self-declared identities.
   Production needs isolation between agents, trusted cross-agent provenance,
   durable replay and audit state, and a real delivery adapter if external
   network effects are desired.
4. **The sentinel must stay simpler than what it guards.** The current host
   launcher starts the stdlib-only sentinel and Firecracker as root and does
   not persist audit logs in abstract mode. Execution mode has durable state
   and a non-root service option; production still needs Firecracker's jailer
   and independently retained checkpoints.

5. **The HTTP boundary is a demonstration interface.** `sentinel.serve`
   authenticates each request with a per-agent HMAC signature and a one-time
   nonce, but replay state is in memory and a guest holding several agent keys
   gives no isolation between those identities. Broker submissions serialize
   state and snapshot the reviewed action, and both HTTP interfaces bound
   request bodies.
6. **Filesystem isolation remains a deployment requirement.** Policy scopes
   match directory components and reject traversal. Execution uses no-follow,
   descriptor-relative opens and create-only writes, but requires a workspace
   that agents cannot mutate directly.

## Execution verification

Follow [EXECUTION_GUIDE.md](EXECUTION_GUIDE.md) for configuration, API contracts,
and recovery. From `sentinel-poc`, run `bash deploy/verify-linux.sh`, or explicitly
select the installed interpreter with `PYTHON=python3`. Local Python 3.12.13 checks
passed all 23 abstract tests, 4 HTTP demo tests, 33 execution tests, and the
original demo. Deployment shell syntax also passed. Python 3.13 itself remains
unverified in this environment.

Full enforcement completed all four benign evaluation tasks and blocked all
four adversarial cases without harmful effects. The capability-only baseline
allowed two synthetic leaks to a loopback mock service. Raw counts and limitations
are in [evaluation-report.json](sentinel-poc/evaluation-report.json).

Authenticated Firecracker boot remains unverified because Firecracker and guest
images are unavailable. Production jailer integration and automatic independent
checkpoint export remain operator work. No live NVIDIA check was run for these changes.
