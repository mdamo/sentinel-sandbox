# Sentinel trusted execution: Linux operator guide

## Modes and isolation

The existing local/live demos and `sentinel.serve` remain abstract decision
demonstrations. The opt-in `sentinel.execution_service` performs workspace reads,
create-only writes, scoped HTTP POSTs, scoped DNS resolution, and ephemeral
messages. It never executes Python, a shell, or another agent-selected binary.

The trusted service must own the workspace, configuration, database, audit key,
and outbound connections. Agents need a separate identity/VM and no direct access
to those resources. A same-user Unix-socket demo tests the API, not hostile-agent
isolation. Use TLS for microVM agents and provision only each agent's credential
and the public certificate authority; keep all operator secrets on the host.

## File-only setup

Run as the intended non-root service account. The initializer refuses to replace
an existing directory and generates private configuration and random credentials.
Python 3.13 is the documented target; these changes were tested on Python 3.12.3.

```bash
cd /path/to/sentinel-sandbox/sentinel-poc
python3.13 deploy/init-execution.py /path/to/new-private-run
python3.13 -m sentinel.execution_service \
  --config /path/to/new-private-run/config.json \
  --unix /path/to/new-private-run/control.sock
```

From a second terminal:

```bash
python3.13 -m swarm.execution_client \
  --unix /path/to/new-private-run/control.sock \
  --credential-file /path/to/new-private-run/agent-1.token \
  --request-file /path/to/new-private-run/read-request.json
```

The result contains `public task\n`. The generated capabilities allow reads in
`input` and create-only writes in `output`, with no network or message permissions.
The client reads tokens from files instead of exposing them in command arguments.
Use `--output NEW_PATH` to write a response to a new mode-0600 file. Display only
public fixture results in terminals. Keep `operator.token` and `config.json`
outside agents and guest images.

## Configuration and API

Configuration/credential files require mode 0600. Workspace and database-parent
directories require service ownership and mode 0700; the Unix socket parent has
the same requirement. Keep directories free of untrusted mutations and mounts.

Each credential maps to `{name, swarm, run, admin}` and must contain at least
32 characters. Agent identities must have configured capabilities; all identities
must match the run/swarm. Caller-supplied `agent_id` must match the authenticated
identity. Admin credentials cannot execute agent operations. Credential rotation
requires operator configuration changes and restart; no issuance endpoint exists.

Capability entries contain `types`, `hosts`, `read`, `write`, and `endpoints`.
Requests require a bearer token, one Content-Length, and at most 65536 bytes.
Transfer encoding and numeric caller-supplied `derived_from` IDs are rejected.
The service permits at most 16 concurrent HTTP handlers.

```json
{
  "request_id": "unique-for-this-agent-and-run",
  "type": "file_read",
  "params": {"path": "input/task.txt"},
  "dependencies": []
}
```

| Type | Parameters | Effect |
|---|---|---|
| `file_read` | `path` | Bounded UTF-8 regular-file read |
| `file_write` | `path`, `payload` | Create a new regular file; no overwrite |
| `net_send` | `endpoint`, `payload` | One operator-configured HTTP POST |
| `dns_resolve` | `endpoint` | Resolve the exact configured endpoint host |
| `bus_publish` | `recipient`, `topic`, `payload` | Create an ephemeral recipient-owned result |

Paths are relative to the workspace. Absolute paths, empty components, `.` and
`..` are rejected. Descriptor-relative no-follow opens reject symlinks, hardlinks,
and non-regular files. Writes refuse existing targets and require existing parent
directories. Policy scopes match directory components rather than string prefixes.

Responses include `allow`, `rule`, and `status`, distinguishing permission from
completion. Completed HTTP requests include their HTTP status; a remote 4xx/5xx
still means the request completed, and task correctness must be assessed separately.

## Network and message scopes

Each named endpoint fixes scheme, host, port, POST method, exact route, payload
limit, response limit, and optional IP pins. Agents need both the endpoint name
and host in their capabilities and cannot provide arbitrary URLs, headers, ports,
methods, or routes. Example trusted endpoint configuration:

```json
{
  "report": {
    "host": "api.example.com",
    "scheme": "https",
    "port": 443,
    "method": "POST",
    "route": "/result",
    "allowed_ips": [],
    "max_payload": 16384,
    "max_response": 16384,
    "response_sensitive": true
  }
}
```

Place this map under `endpoints`; replace the example destination with your
intended service and grant `net_send`, that host, and `report` to the chosen
agent. All DNS answers are validated before connecting to a checked address;
TLS verifies the configured hostname. Unexpected non-global addresses are
rejected unless explicitly pinned. Plain HTTP is limited to pinned loopback
fixtures. Redirects are rejected. System CA verification is enabled; optional
trusted `ca_file` supplies a private CA. DNS uses a bounded helper process;
HTTP operations have deadlines and bounded response bodies.

Payloads are bounded text, not an application-specific command schema. Add
business/schema validation before allowing an endpoint with privileged semantics.
The application budget is not packet-level metering of DNS retries or TLS framing.

Messages require explicit sender/recipient pairs in `share_pairs` and permitted
`topics`. The returned handle belongs to the recipient. Authenticated
`POST /receive` with `{ "handle": "..." }` returns that owner's in-memory result
after ownership and quarantine checks. No external message bus is opened.

## Sensitivity and provenance

Only completed operations issue opaque handles. Dependencies must refer to
handles owned by the caller in the current run. Messages explicitly create
recipient-owned handles; arbitrary cross-agent references are denied.

Reads in `sensitive_paths` label the agent context before dispatch, closing the
race with concurrent output. Context sensitivity persists across requests and
restart even when dependencies are omitted. Sensitive writes label the destination
for subsequent readers. Sensitive contexts cannot send HTTP, DNS, or messages.
HTTP response data defaults to sensitive; set `response_sensitive: false` only
for an explicitly public endpoint. Failed operations may conservatively leave
labels attached. Resume does not declassify data; no declassification endpoint exists.

Sensitive prompt content or input from channels outside the runtime needs trusted
classification before reaching an agent. These controls cannot recognize every
secret from an unmodelled source.

## Reservations, retries, and restart

Authorization/state transitions are serialized. Reservations and labels are
durably recorded before dispatch. The global lock is released during slow effects.
Quarantine denies new operations; already admitted operations may finish. Resume
is refused while an admitted operation remains pending.

HTTP reserves its complete generated application request plus a 4096-byte DNS
allowance; DNS-only requests reserve that allowance. Messages charge their encoded
envelope. Successful HTTP request bytes are recorded separately. Reservations
are never refunded, including after partial or uncertain effects. Byte, request,
and destination counters survive restart. Enforce packet/resource limits at the
host too if those are required by your threat model.

An identical request ID returns recorded metadata without another effect.
Conflicting reuse is denied. Dispatched failures are conservatively uncertain
and quarantine the run. Pending operations become uncertain on restart and are
never automatically replayed. This is at-most-once dispatch with retained run
state, not universal exactly-once delivery to an external service.

Policy/run/configuration mismatch with the existing database fails startup.
Migration must be explicit; never delete the database to resume a quarantined run.
Payloads/results remain in memory only: replays return metadata, not content,
and `/receive` cannot recover old contents after restart. Lost results do not
authorize repeating writes or network effects.

## Recovery and audit

Use the operator credential for `POST /admin/resume` with:

```json
{"reason": "reviewed incident and approved recovery", "incident": 12}
```

The incident must match the current active incident's audit sequence in security
state. Recovery clears broker quarantine/agent blocking while preserving budgets,
context/file labels, handles, and idempotency outcomes. The administrator, reason,
incident, and policy version are audited. Put no secrets in review reasons.

SQLite stores immutable JSON audit snapshots, chain links, a state digest, and
HMAC-authenticated security state. A process lock rejects a second writer.
Durable recording failure stops new effects. Audit includes authenticated identity,
run/request IDs, policy version, operation fingerprints, dependencies, reservations,
and outcome; it omits payloads and credentials. Losing the audit key prevents safe
state authentication. A trusted service compromise that obtains the key remains
inside the trust boundary.

Submit `{}` to `/admin/checkpoint` with the operator credential and save the
response using `swarm.execution_client --output`. Retain it in an independently
controlled store along with a trusted copy of the audit key. After stopping the
service, verify:

```bash
python3.13 -m sentinel.verify_audit \
  --database /path/to/new-private-run/state.sqlite \
  --checkpoint /independent/store/checkpoint.json \
  --key-file /independent/store/audit-key.hex
```

The private key file contains the original `audit_key_hex` value. Automatic remote
checkpoint shipping is not implemented. Local records alone cannot independently
prove that an entire database was not rolled back. Retained external checkpoints
detect rollback past the checkpoint and changes to its committed audit prefix.

## Verification and measured limits

```bash
cd /path/to/sentinel-sandbox/sentinel-poc
bash deploy/verify-linux.sh
# Explicit fallback when Python 3.13 is unavailable:
PYTHON=python3 bash deploy/verify-linux.sh
```

The runner performs abstract tests, execution tests, the demo, evaluation, and
whitespace checks. Tests use temporary files and loopback HTTP/TLS fixtures;
OpenSSL is needed for the local TLS fixture, which reports a skip if absent.
The current verified local results on Python 3.12.3 are 19 abstract tests and
26 execution tests passing, the original 15-action/7-denial demo passing, and
deployment shell syntax checks passing. Python 3.13 itself remains unverified here.

| Evaluation mode | Benign completion | Adversarial cases blocked without effect | Synthetic harmful effects |
|---|---|---|---|
| Capability-only | 4/4 | 2/4 | 2 |
| Full enforcement | 4/4 | 4/4 | 0 |

Full mode generated two review signals on benign cooperation and zero false
blocks. Execution correlation is run-scoped, has a 300-second window, and produces
review signals; `workflow_hosts` suppresses expected cooperation signals. Abstract
demos retain blocking correlation rules. Capability-only is an evaluation baseline,
not a service configuration option.

`sentinel-poc/evaluation-report.json` contains raw outcomes, timings, parent CPU
time, process peak RSS, and limitations. It uses one repetition of eight controlled
workloads and makes no general coverage/performance claim. Concurrency, crash,
storage-failure, and recovery correctness are tested separately. No live NVIDIA
check was performed for these changes.

## Authenticated Firecracker smoke test

The default boot test remains abstract. The optional execution mode requires
Firecracker, KVM, Python 3.13, a guest kernel, rootfs-building dependencies, and
a dedicated non-root host service user. Prepare the file-only configuration as
that service user. Provision a TLS certificate with IP SAN `172.16.0.1`; its
private key stays host-side. The guest receives only its agent token and public CA.

```bash
sudo EXECUTION_GUEST_TOKEN_FILE=/private/run/agent-1.token \
  EXECUTION_CA_FILE=/private/certs/ca.pem \
  EXECUTION_HOST_WORKSPACE=/private/run/workspace \
  deploy/microvm/build-rootfs.sh /path/to/new-execution-agent.ext4

sudo KERNEL_IMAGE=/path/to/vmlinux \
  ROOTFS_IMAGE=/path/to/new-execution-agent.ext4 \
  SENTINEL_EXEC_CONFIG=/private/run/config.json \
  SENTINEL_TLS_CERT=/private/certs/server.pem \
  SENTINEL_TLS_KEY=/private/certs/server.key \
  SENTINEL_SERVICE_USER=sentinel \
  deploy/microvm/test-boot.sh
```

The rootfs contains a scoped credential and is created with mode 0600. The guest
client runs as UID 10002. The host execution service runs under the named non-root
account. The boot fixture expects the initializer's `input/task.txt` and permission
to create `output/boot-*.txt`. It checks authenticated adapter reads/writes,
unauthenticated denial, and failed direct host-network/workspace access. Direct
connection failures are integration signals, not proof of complete firewall policy.

Authenticated boot has not been run here: Firecracker and guest images are
unavailable. The launcher still lacks a Firecracker jailer and production host
hardening. `deploy/sentinel-execution.service` is an uninstalled systemd template
with an unprivileged account and resource limits; review its paths and adapt Unix
transport to TLS for microVM use. Production jailer deployment and independent
checkpoint shipping remain operator integration work.
