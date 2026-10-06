# Execution service security fixes

The October 6 review found five issues addressed by these changes. These fixes
do not establish production readiness of the Firecracker deployment.

## Sensitive files and malformed requests

File labels can only gain sensitivity. A failed create-only write cannot erase
an existing label. A file read reconciles its labels again under the broker lock
after reading, and persists the reader context and result labels before returning
data. This covers a sensitive file created between read admission and dispatch.
The workspace must still be inaccessible to direct agent mutation.

Malformed Unicode in requests is rejected as `request-text` before reservation.
It no longer changes service health. Invalid credential text is rejected as
`authentication`.

## Connection deadlines

The execution API allows 16 workers. TLS handshakes run in those workers with a
five-second handshake timeout. HTTP request lines, headers and bodies share an
absolute five-second read deadline, including Unix connections and clients that
send bytes slowly. The read deadline ends once the complete body is received;
adapter operations retain their own timeouts. Disconnected clients do not
authorize replaying an effect.

## Durable admission limits

Execution configuration accepts `max_agent_admissions` (default 1024) and
`max_run_admissions` (default 4096). Both must be integers from 1 through 100000.
These limits are separate from existing effect budgets. They count new execute
attempts, including malformed and denied requests, and result-receipt attempts.
Charges persist with the audited operation or rejection. Concurrent requests
share the same limits. Administrator resume never resets them.

Once a limit is exhausted, new attempts receive `admission-limit` without a new
audit row or state mutation. The last admitted event retains the exhausted
counter in signed state. Further rejected attempts are intentionally not logged
individually. Limits are per run, not time windows. Operator endpoints are not
subject to agent admission quotas.

Identical recorded execute retries remain available at the limit and do not
consume another admission or repeat an effect. No retry history is evicted.
Result receipt consumes an admission; choose limits that leave room for receipts.

The SQLite state remains a complete, bounded snapshot. New request/handle and
file-label records are bounded by admissions; each commit serializes its stored
snapshot once. Exhausted-agent traffic cannot grow those snapshots or the audit.
This deliberately retains a finite-run architecture rather than introducing
unsafe eviction of idempotency records. Large configured runs still have larger
snapshot costs and should be load-tested with their actual payload limits.

Existing signed databases with the previous configuration format are upgraded
in place after signature/configuration verification. Existing audit events are
counted toward the new admission limits, with no loss of labels, effect budgets,
retry history or pending-operation recovery. The upgrade is audited. A later
change to configured admission limits requires explicit migration, like other
policy changes. Already exhausted legacy runs remain exhausted. The upgrade
cannot reconstruct sensitive labels previously erased by the old write bug;
operators must review potentially affected existing workspaces before resuming.

## Verification

Run `python3 test_runtime.py`, `python3 test_sentinel.py`, `python3 run_demo.py`,
and `python3 evaluate_runtime.py --output /tmp/sentinel-evaluation.json`.
Regression tests cover concurrent read/create, failed writes, invalid Unicode,
idle/dripping HTTP clients, stalled TLS handshakes, concurrent admission limits,
replays at exhaustion, restart, and legacy signed-state upgrade. Tests use
synthetic data, temporary files and local network fixtures.

Python 3.13 and Firecracker boot must still be verified on the target host.
The launcher still requires production jailer integration and independent audit
checkpoint retention as described in the repository execution guide.
