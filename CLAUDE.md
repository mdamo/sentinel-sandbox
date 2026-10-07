# CLAUDE.md — guidance for an AI assistant working on this repo

This file orients another LLM (or a future session) picking up **sentinel-poc**.
Read it before editing. It records what exists, the invariants that must hold,
and the things that are easy to get wrong.

## What this project is

A proof of concept for a **deterministic sentinel** that contains a swarm of AI
agents running in a sandbox. Agents run in a "cell"; a separate, trusted sentinel
is the single door every action must pass through. The sentinel's decisions are
deterministic — no LLM in the decision path, same input → same decision, every
decision explained by the name of the rule that fired.

Motivation: the July 2026 OpenAI eval escape, where models broke out through the
*one permitted egress channel*. Lesson encoded here: an allowlist is necessary
but not sufficient, so the sentinel adds stateful, swarm-aware checks on top.

## Safety framing — DO NOT BREAK THIS

This is defensive tooling plus a test harness. The local demo performs no
effects. The HTTP host adapter performs confined file reads/writes and appends
local outbox/bus records; it opens no outbound socket or subprocess. The
microVM launcher configures a local TAP/firewall, and the guest agents send
signed action records to the host sentinel. The "attacks" in
`swarm/scenarios.py` remain abstract action records, NOT working attack code.

The user authorized `LINUX_IMPLEMENTATION_PLAN.md`, including an opt-in trusted
execution service with real scoped file/HTTP effects. Keep it separate from the
abstract demos; its adapter tests use temporary files and local HTTP/TLS fixtures.
See `EXECUTION_GUIDE.md` for configuration and security contracts.

If asked to extend the abstract attack scenarios, keep them at the same abstract level —
add new `Action` shapes and expected-deny rules, never real exploit code, real
network calls, or embedded credentials. The value is in showing the sentinel
*denies* the pattern, not in demonstrating the exploit.

## Architecture (data flow)

```
agent → Action (typed intent) → Broker.submit()
                                   ├─ Policy.evaluate()   (allow in isolation?)
                                   └─ Monitor.review()    (allow given all state?)
                                 → Decision(allow, rule, reason, taints)
```

| File | Responsibility |
|---|---|
| `sentinel/actions.py` | `Action`, `ActionType`, `Decision`. The finite action vocabulary. |
| `sentinel/policy.py` | Deterministic, stateless, per-action checks. `Capability` per agent. |
| `sentinel/monitor.py` | Stateful: budgets, taint, provenance, swarm correlation. Also applies the response policy + emits alerts. |
| `sentinel/response.py` | `ResponseMode`, `ResponsePolicy`, `Alert`. Maps a fired rule → escalation (deny / kill agent / quarantine swarm). |
| `sentinel/broker.py` | Single enforcement point + hash-chained `AuditLog` (`verify()`). Complete mediation. |
| `sentinel/serve.py` | Stdlib HTTP front end on the Linux host. |
| `sentinel/identity.py` | Signed requests and replay checks with per-agent keys. |
| `sentinel/effects.py` | Confined host file effects and local send/bus records. |
| `swarm/catalog.py` | Shared six-agent roster and six tool names. |
| `swarm/ai_agents.py` | Model proposal interface, offline backend, and mediated tools. |
| `swarm/nemotron.py` | Stdlib NVIDIA HTTPS proposal transport, repository `.env` loading, strict JSON parsing. |
| `swarm/live_demo.py` | Fetch and validate all six live proposals before submitting any abstract actions. |
| `swarm/scenarios.py` | Abstract benign + misbehaving agent behaviours. |
| `swarm/agent_client.py` | In-guest agent that POSTs actions to the sentinel. |
| `run_demo.py` | End-to-end demo with audit log + verdict table. |
| `test_sentinel.py` | Pattern, omitted-provenance, and authenticated HTTP effect checks. 23 tests. |
| `test_http_client.py` | Repeat-run HTTP demo regressions (shared server, budgets, correlation). |
| `sentinel/runtime.py` | Authenticated execution, durable sensitivity/handles, reservations, idempotency, admin recovery. |
| `sentinel/adapters.py` | Scoped file and pinned-address HTTP/DNS effects; arbitrary tools disabled. |
| `sentinel/storage.py` | Single-writer SQLite, audit chain, signed state/checkpoints. |
| `sentinel/execution_service.py` | Opt-in Unix/TLS API with bounded handlers and authenticated identities. |
| `test_runtime.py` | 33 stdlib execution/concurrency/recovery tests with controlled fixtures. |
| `evaluate_runtime.py` | Eight workloads comparing capability-only and full enforcement. |
| `deploy/microvm/` | Firecracker guest builder, Linux host launcher, and boot integration test; no Docker runtime. |

## Invariants — must stay true after any change

0. **Detection ≠ response.** A deny always blocks first. Escalation (kill agent /
   quarantine swarm) is decided by `ResponsePolicy` in `response.py`, applied in
   `Monitor._respond`. Keep the mapping data-driven; don't re-hard-code kills in
   the review logic. `DENY_ONLY` must emit no alert; the other modes always alert.
1. **No LLM in the decision path.** `Policy` and `Monitor` are pure Python logic.
   Untrusted agent models may propose actions through the broker, never decide
   permission. A trusted LLM advisor may only be added *off the critical path* and
   proposes *stricter* rules or flags for a human — never to make an allow.
   `on_alert` is the hook where a human/LLM advisor would receive events.
2. **Monitor can only make a decision stricter, never looser.** It runs after the
   policy and may downgrade an allow to a deny, never the reverse.
3. **Default-deny.** Anything not explicitly granted by a `Capability` is denied.
   New action types must be added to `ActionType` *and* given a handler in
   `Policy.evaluate`, or they are denied by `capability-type`.
4. **Fail closed.** Any internal error in the broker yields a deny
   (`rule="fail-closed"`), never an allow. See `Broker.submit`'s try/except.
5. **Every Decision names the rule that fired.** The `rule` string is the audit
   contract and is asserted by the tests. If you rename a rule, update the tests,
   the README tables, and any `ResponsePolicy` mapping in the same change.
   The audit log is hash-chained: never mutate a past `AuditEntry`; `verify()`
   must stay true for an untampered run.
6. **Taint follows data and agent history.** Reads of `sensitive_prefixes`
   attach a `sensitive:` taint; it propagates through `Action.derived_from` and
   persists on the agent identity, so omitted provenance cannot clear it for
   that agent. Any outbound action carrying it is denied by `taint-egress`.
   Don't drop the propagation in `Monitor._inherited_taint` / `record_result`.
   Execution mode also labels agent contexts and files durably before dispatch;
   sensitive outputs must be denied even when dependencies are omitted.
7. **The host-side sentinel stays stdlib-only.** It guards everything, so it
   must stay small and auditable. The guest image is read-only and the guest
   agent runs as an unprivileged UID. Host network rules must continue to deny
   guest traffic except to the sentinel.

## Rule catalogue (the `rule` strings the tests assert)

`no-capability`, `capability-type`, `canary-tripwire`, `egress-allowlist`,
`dns-allowlist`, `fs-read-scope`, `fs-write-scope`, `tool-allowlist`, `bus-open`,
`agent-killed`, `swarm-quarantined`, `taint-egress`, `budget-agent`,
`budget-swarm`, `corr-split-role`, `corr-split-payload`, `fail-closed`.

## How to run / verify

```bash
cd sentinel-poc
python3.13 run_demo.py    # expect: ALL SCENARIOS BEHAVED AS EXPECTED, 6 denied,
                          #         audit chain verifies: True, quarantine demo
python3.13 test_sentinel.py # expect: 23/23 tests passed   (pytest also works)
python3.13 test_http_client.py # expect: OK (4 tests)

# test_sentinel.py includes an HTTP boundary test with signed requests and effects.
# test_http_client.py runs the six-role guest client twice against one server.

# microVM (requires a Linux KVM host, Firecracker, guest kernel, and rootfs):
# Create SENTINEL_KEYS_FILE as documented in README, with a key for each of the
# six roster agents; use the same file throughout.
sudo SENTINEL_KEYS_FILE=/path/to/keys.json deploy/microvm/build-rootfs.sh /path/to/agent.ext4
sudo SENTINEL_KEYS_FILE=/path/to/keys.json KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 deploy/microvm/run.sh
sudo SENTINEL_KEYS_FILE=/path/to/keys.json KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 deploy/microvm/test-boot.sh
```

**Always run `run_demo.py`, `test_sentinel.py` and `test_http_client.py` after a
change** and confirm the counts above before claiming it works.

For execution changes also run `python3.13 test_runtime.py` and
`python3.13 evaluate_runtime.py --output evaluation-report.json`, or run
`bash deploy/verify-linux.sh`. Report interpreter substitutions explicitly.
OpenSSL is required for the local TLS fixture; a missing tool produces a skip.
Authenticated Firecracker tests require fresh guest provisioning and are separate
from local tests. Current checks passed on Python 3.12.3, not Python 3.13.

## Live NVIDIA proposal backend

- Run `python3.13 -m swarm.live_demo` from `sentinel-poc`; `--model` and
  `--task` override the model and task. This is a local process, not a microVM.
- Default: `nvidia/nemotron-3.5-lightning-30b-a3b`. The old
  `nvidia/nemotron-nano-3-30b-a3b` returned 404; the corrected older ID
  `nvidia/nemotron-3-nano-30b-a3b` returned 410 with an end-of-life date of
  September 1, 2026. Verify current availability before changing model IDs.
- Settings load from the repository-root `.env` beside this file:
  `NVIDIA_API_KEY`, `NVIDIA_MODEL`, `NVIDIA_BASE_URL`, and `LOG_LEVEL`.
  Existing environment variables take precedence. Never print the API key.
- Base URL defaults to `https://integrate.api.nvidia.com/v1`; the client
  appends `/chat/completions` and requires HTTPS and a Nemotron model prefix.
- Requests use JSON response mode, disabled thinking, temperature zero,
  a 2048-token output limit, a 60-second timeout, and no retries or fallback.
- Proposals contain one to six recognized calls with string-valued arguments.
  `run_python` takes empty arguments; proposals never execute Python code.
- Preserve batch validation: transport errors, incomplete responses, and
  malformed proposals must stop the demo before any broker submission.
- Live availability and model formatting require a separate live check; the
  19 offline tests and local demo do not establish live-provider success.

Verification on October 3, 2026: all 19 offline tests and the local demo
passed. The replacement accepted live requests, but checks encountered an
incomplete response, malformed JSON, and provider timeouts. The final live
run timed out before submitting actions; a successful six-agent live run
has not yet been verified.

## Known limits (already documented in README — keep them honest)

- The Firecracker guest gives a separate kernel boundary. The PoC launcher does
  not use Firecracker's jailer or production resource limits; the Linux host,
  KVM, and firewall remain trusted.
- Deterministic means it only catches specified patterns; the correlation rules
  are illustrative and need a tuned, reviewed catalogue in production.
- Agent-history taint blocks omitted provenance for the same identity, at the
  cost of denying later clean outbound work. HTTP identity is authenticated,
  but cross-agent provenance is still self-declared. The guest holds the keys
  of all six roster agents, so per-agent isolation inside one guest is still
  missing; replay state is currently in memory.
- Abstract taint tracking relies on `derived_from`; execution mode validates
  handles and keeps sticky contexts. Unmodelled inputs need trusted classification.
- Execution payloads are memory-only; restart retains labels and metadata but
  cannot return old result content. Never replay effects merely to recover results.
- Reservations are charged without refunds. DNS uses an application allowance,
  not packet-level accounting. Pending effects become uncertain on restart.
- Execution correlation is review-only with a bounded window; the abstract
  demos retain blocking rules. Workflow permissions suppress expected signals.
- Storage failure prevents new effects. Resume must preserve budgets, sensitivity,
  and idempotency; uncertain effects must never be automatically replayed.
- Production jailer integration and automatic remote checkpoint export remain
  unimplemented. Do not describe the microVM smoke-test launcher as hardened.

## Conventions

- Python 3.13, standard library only. No runtime third-party deps.
- Dataclasses for state; `Enum` for action types.
- Keep `policy.py` stateless. Abstract state belongs to `Monitor`, HTTP replay
  state to `IdentityStore`, and execution state to `Runtime` and its SQLite
  transitions under the broker lock; don't bypass those locks at the HTTP boundary.
- When adding a pattern: add the abstract scenario, add a handler/rule if needed,
  add a test asserting the exact `rule`, update both README tables and this file.
