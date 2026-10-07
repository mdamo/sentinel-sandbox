# Sentinel: five-step Linux implementation and verification plan

## Status and scope

The five steps now have a local implementation. See `EXECUTION_GUIDE.md` for
configuration/operation and `sentinel-poc/evaluation-report.json` for raw results.
The original abstract demos remain intact; real effects use a separate opt-in service.

Local Python 3.12.3 checks passed 19 abstract tests, 26 execution tests, the
original 15-action/7-denial demo, evaluation, and deployment shell syntax.
Full evaluation completed four benign tasks and blocked all four adversarial
cases without a harmful effect; capability-only allowed two synthetic leaks
to the local mock service. No general coverage claim follows from this finite suite.

Python 3.13 and authenticated microVM boot remain unverified here. Firecracker
and guest images are unavailable. Production Firecracker jailer deployment and
automatic independent checkpoint shipping remain operator integration work.
No live NVIDIA check was run. This work is uncommitted for review.

The original demos mediate abstract action records. Opt-in execution adds real
file and network effects. Keep the existing abstract demos intact;
introduce real execution only through explicit, narrowly scoped adapters and
test them with temporary files and local services. Do not add exploit code or
send real secrets to external services.

Read `CLAUDE.md`, `README.md`, and any applicable `AGENTS.md` before changing
code. Update the documentation's abstract-only statements when adapters exist,
so the supported execution modes and their limits remain clear.

## Linux preparation

From your checkout, use Python 3.13 as documented by the project:

```bash
cd /path/to/sentinel-sandbox
git status --short
python3.13 --version
cd sentinel-poc
python3.13 test_sentinel.py
python3.13 run_demo.py
```

Record the baseline output. Preserve unrelated local changes. Work on a new
branch if your checkout permits it. The existing direct runner documents 19
tests; extend its discovery or registration when adding tests, rather than
assuming newly written tests will run automatically.

## 1. Trusted execution, identity, and provenance

Relevant files: `sentinel/broker.py`, `sentinel/actions.py`,
`sentinel/serve.py`, and `swarm/ai_agents.py`.

Implement a trusted executor behind the broker. It must validate a request,
authorize it, and perform exactly the authorized effect. An allow decision
returned to an untrusted agent is not an execution boundary. Agents must have
no alternative route to the protected filesystem, credentials, or network.

Start with workspace file read/write and a narrowly defined HTTP operation.
Keep arbitrary Python or shell execution disabled in real-execution mode;
an executable-name allowlist does not constrain its behavior. Retain the
abstract `tool_exec` demo separately.

Bind identities to authenticated credentials or trusted transport identities;
never trust the submitted `agent_id`. Scope credentials to a particular agent,
swarm, and run. Reject identity mismatches. Keep credentials out of logs and
restrict the service listener; loopback alone does not authenticate callers.
Use TLS or an appropriately protected local transport for credentials.

Have the trusted runtime issue opaque result handles and record their owner,
run, sensitivity, and dependencies. Reject forged, unknown, denied-action,
cross-run, or unauthorized cross-agent references. Resolve handles on the
trusted side instead of accepting caller claims about provenance.

Result handles alone cannot track a model copying sensitive text into a new
literal. Choose and document a conservative policy: once an agent receives
sensitive data, taint its execution context and subsequent outputs; propagate
that context through messages and delegation. Permit declassification only
through a trusted, explicitly authorized operation. Test omitted provenance.

Acceptance criteria:

- An unauthenticated or impersonating client cannot execute effects.
- A denial produces no protected filesystem or network effect.
- Approved operations execute only through the trusted adapter.
- Omitting provenance cannot turn a sensitive output into an untainted output.
- Forged handles and unauthorized cross-agent dependencies are denied.

## 2. Atomic budgets and concurrent state

Relevant files: `sentinel/broker.py`, `sentinel/monitor.py`, and
`sentinel/serve.py`.

Serialize the full authorization/state transition with a broker-owned lock,
or use equivalent transactional storage. Include quarantine checks, budget
reservation, correlation state, provenance registration, and audit ordering.
The threaded HTTP server must not independently mutate these shared structures.

Define reservation and completion semantics for real effects. Reserve capacity
before dispatch; record actual transmitted bytes and execution outcome. Do not
hold a global lock across slow network operations. Bound operation duration
and make failures, cancellations, and partial sends explicit. Conservatively
charge bytes that may have left the system; only refund provably unused capacity.

Add request IDs scoped to authenticated identities and durable idempotency
records. A retry must not repeat an effect. Handle the crash window between
dispatch and completion: if an effect cannot be proven completed or absent,
record it as uncertain and avoid automatic replay. Do not claim universal
exactly-once delivery for external services.

Acceptance criteria:

- Concurrent requests cannot collectively exceed the configured budget.
- Reservations remain bounded after failures and restarts.
- Audit and monitor state use a consistent operation ordering.
- Duplicate request IDs do not repeat effects; conflicting reuse is rejected.
- Tests cover simultaneous requests, partial failure, and quarantine races.

## 3. Canonical paths and narrowly scoped networking

Relevant files: `sentinel/policy.py` and the new execution adapters.

Replace raw string-prefix path checks with directory-bound authorization.
Use Linux directory file descriptors and safe relative opens, rejecting
absolute paths and traversal. Use `openat2` resolution restrictions where
available, or carefully walk components with no-follow directory opens.
Do not rely only on `Path.resolve()` followed by a separate open: filesystem
changes between check and use can invalidate that check. Define how safe
file creation, replacement, and symlinks behave, and test those cases.

Make network permissions describe scheme, host, port, method, route, and
payload constraints. Resolve destinations in the trusted adapter and check
every resolved address against policy. Bind the connection to a validated
address while retaining TLS hostname verification. Reject redirects by
default; if supported, validate each hop. Block unexpected loopback, private,
link-local, and metadata-service addresses unless explicitly required by that
adapter's policy. Enforce response and request size limits and timeouts.

Use exact DNS names by default. The current `_dns` rule permits some subdomains
of allowlisted names; make wildcard permission explicit and deny arbitrary
data-bearing names. Measure encoded wire payloads rather than trusting a
caller-supplied size. Scope message-bus topics, recipients, and payloads too.

Acceptance criteria:

- Traversal, sibling-prefix paths, and symlink substitution cannot escape scope.
- Changes between authorization and execution cannot redirect a file operation.
- Alternate ports, forbidden routes, redirects, and unapproved resolved
  addresses cannot bypass network policy.
- DNS and message-bus permissions do not create unmetered egress channels.

## 4. Durable audit and recoverable quarantine

Relevant files: `sentinel/broker.py`, `sentinel/response.py`,
`sentinel/monitor.py`, and `sentinel/serve.py`.

Persist audit records and security state using transactional storage such as
SQLite for a single-host deployment. Include authenticated identity, run ID,
request ID, policy version, normalized operation, decision, reservation,
execution status, timestamps, and dependencies. Redact payload secrets and
credentials. Preserve immutable snapshots rather than mutable action objects.

Persist quarantine, blocked agents, budgets, and pending operations across
restart. Audit-storage failure must stop new protected effects. Record intent
durably before execution and completion afterward; reconcile pending records
on startup without blindly replaying effects.

A hash chain in the same writable store is not sufficient against deletion or
wholesale rewriting. Export records or signed checkpoints to an independently
controlled store. Document the remaining tamper-evidence limitations.

Add an authenticated administrative review/resume operation, separate from
agent permissions. Require a reason and record the administrator, reviewed
incident, and policy version. Resuming must not silently clear consumed budgets
or sensitive context. Specify whether active requests finish or are cancelled
when quarantine begins. Broker denial alone does not terminate a process or VM.

Acceptance criteria:

- Restart preserves quarantine, budgets, and audit continuity.
- Agent credentials cannot invoke review/resume operations.
- Recovery is audited and does not grant broader permissions implicitly.
- Storage failures prevent new protected effects.
- Crash tests cover pending operations and external checkpoint verification.

## 5. Evaluate useful work alongside adversarial scenarios

Relevant files: `test_sentinel.py`, `swarm/scenarios.py`, and a new documented
evaluation runner/report.

Create reproducible workloads with expected outcomes defined before running:

- Benign: read public data, transform it, and submit a result to a local service.
- Benign: one agent resolves a permitted service and another reports to it.
- Benign: several agents report independently to the same permitted service.
- Adversarial: omit provenance after receiving sensitive input, spoof identity,
  forge dependencies, exceed aggregate budgets, and attempt prohibited paths
  or destinations.
- Operational: duplicate requests, concurrent submissions, timeouts, adapter
  errors, storage failures, restarts, and administrative recovery.

Use abstract requests and controlled local fixtures for adversarial cases.
Use real adapters only against temporary workspaces and local mock services.
Include task correctness assertions; an allowed operation alone is not success.

The current split-role and split-payload heuristics can flag normal cooperation.
Refine them using explicit workflow permissions, run scope, and bounded time
windows. Treat ambiguous patterns as review signals rather than confirmed leaks;
retain hard denial for concrete capability and sensitive-egress violations.
Do not loosen a rule merely to make a benchmark pass.

Report workload counts and outcomes, harmful effects prevented, false denials,
benign task completion, end-to-end latency, broker latency, and resource use.
Separate false alerts from false blocks. Compare the same workloads against
capability-only enforcement and the full monitor. Publish limitations and
failures; passing a finite suite does not establish universal containment.

Acceptance criteria:

- Benign collaboration completes with correct results under documented policy.
- Prohibited operations cause no protected effect in the controlled fixtures.
- Concurrent and restart tests reproduce the intended security invariants.
- The report includes raw counts, configurations, and reproducible commands.

## Verification and Linux/KVM deployment

After implementing the changes, run the extended test runner and existing
demo, then the new adapter/concurrency/recovery evaluation commands documented
by that implementation:

```bash
cd /path/to/sentinel-sandbox/sentinel-poc
python3.13 test_sentinel.py
python3.13 run_demo.py
git diff --check
```

The live model demo is optional and requires NVIDIA credentials. It is separate
from testing the execution boundary and consumes external API requests:

```bash
python3.13 -m swarm.live_demo
```

For the microVM integration test, use a Linux/KVM host with the dependencies
listed in `README.md`. Inspect deployment scripts before running them as root.
Build a fresh rootfs after changing guest code:

```bash
sudo deploy/microvm/build-rootfs.sh /path/to/agent.ext4
sudo KERNEL_IMAGE=/path/to/vmlinux ROOTFS_IMAGE=/path/to/agent.ext4 \
  deploy/microvm/test-boot.sh
```

The existing boot smoke test exercises abstract decisions only. Extend it to
verify authenticated adapter use and denied direct access to protected network
and filesystem resources. Before production deployment, use Firecracker's
jailer, an unprivileged sentinel service account, resource limits, and an
independent audit destination. Do not place host credentials in the guest.

Complete the handoff with implementation commit IDs, exact test commands,
evaluation output, deployment configuration, and remaining limitations.
