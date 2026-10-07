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
microVM launcher configures a local TAP/firewall. The "attacks" in
`swarm/scenarios.py` remain abstract action records, NOT working attack code.

If asked to extend the attack scenarios, keep them at the same abstract level —
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
| `swarm/scenarios.py` | Abstract benign + misbehaving agent behaviours. |
| `swarm/agent_client.py` | In-guest agent that POSTs actions to the sentinel. |
| `run_demo.py` | End-to-end demo with audit log + verdict table. |
| `test_sentinel.py` | Pattern, omitted-provenance, and authenticated HTTP effect checks. 23 tests. |
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

# test_sentinel.py includes an HTTP boundary test with signed requests and effects.

# microVM (requires a Linux KVM host, Firecracker, guest kernel, and rootfs):
# Create SENTINEL_KEYS_FILE as documented in README; use the same file throughout.
sudo SENTINEL_KEYS_FILE=/path/to/keys.json deploy/microvm/build-rootfs.sh /path/to/agent.ext4
sudo SENTINEL_KEYS_FILE=/path/to/keys.json KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 deploy/microvm/run.sh
sudo SENTINEL_KEYS_FILE=/path/to/keys.json KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 deploy/microvm/test-boot.sh
```

**Always run both `run_demo.py` and `test_sentinel.py` after a change** and
confirm the counts above before claiming it works.

## Known limits (already documented in README — keep them honest)

- The Firecracker guest gives a separate kernel boundary. The PoC launcher does
  not use Firecracker's jailer or production resource limits; the Linux host,
  KVM, and firewall remain trusted.
- Deterministic means it only catches specified patterns; the correlation rules
  are illustrative and need a tuned, reviewed catalogue in production.
- Agent-history taint blocks omitted provenance for the same identity, at the
  cost of denying later clean outbound work. HTTP identity is authenticated,
  but cross-agent provenance is still self-declared. Keys in a shared guest
  would need per-agent isolation; replay state is currently in memory.

## Conventions

- Python 3.13, standard library only. No runtime third-party deps.
- Dataclasses for state; `Enum` for action types.
- Keep `policy.py` stateless. Monitor state, HTTP replay state, and broker
  serialization are separate; don't bypass their locks at the HTTP boundary.
- When adding a pattern: add the abstract scenario, add a handler/rule if needed,
  add a test asserting the exact `rule`, update both README tables and this file.
