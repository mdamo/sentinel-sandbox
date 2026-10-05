"""Authenticated durable execution boundary, separate from the abstract demos.

One service process owns a run/database. Budgets reserve conservatively before
dispatch. Admitted operations finish if quarantine starts; new ones are denied.
No uncertain operation is automatically replayed. Payloads never enter audit.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass

from .actions import Action, ActionType, Decision
from .adapters import Adapters, Rejected
from .broker import Broker
from .monitor import Monitor, Budget
from .policy import Policy, in_scope
from .response import ResponsePolicy
from .storage import Store, canonical


@dataclass(frozen=True)
class Identity:
    name: str
    swarm: str
    run: str
    admin: bool = False


@dataclass
class ReservedAction(Action):
    reserved: int = 0

    def size(self):
        return self.reserved


class Runtime:
    def __init__(self, policy: Policy, adapters: Adapters, store: Store,
                 credentials: dict[str, Identity], *, swarm: str, run: str,
                 policy_version: str, audit_key: bytes,
                 per_agent: Budget = None, per_swarm: Budget = None,
                 share_pairs: frozenset[tuple[str, str]] = frozenset(),
                 topics: frozenset[str] = frozenset(),
                 endpoint_grants: dict[str, frozenset[str]] | None = None,
                 workflow_hosts: frozenset[str] = frozenset(),
                 capability_only: bool = False):
        if not audit_key or len(audit_key) < 32 or not credentials:
            raise ValueError("credentials and >=32-byte audit key required")
        self.credentials = {}
        for token, identity in credentials.items():
            if len(token) < 32 or identity.swarm != swarm or identity.run != run:
                raise ValueError("invalid credential scope or strength")
            if not identity.admin and identity.name not in policy.capabilities:
                raise ValueError("credential identity lacks capability")
            self.credentials[hashlib.sha256(token.encode()).digest()] = identity
        self.swarm, self.run, self.policy_version = swarm, run, policy_version
        self.key, self.adapters, self.store = audit_key, adapters, store
        self.share_pairs, self.topics = share_pairs, topics
        self.endpoint_grants = {k: frozenset(v) for k, v in (endpoint_grants or {}).items()}
        self.capability_only = capability_only  # evaluation baseline; not exposed in service CLI
        monitor = Monitor(per_agent or Budget(100000, 100, 10),
                          per_swarm or Budget(1000000, 1000, 20),
                          response=ResponsePolicy.strict(), correlation_enforce=False,
                          workflow_hosts=workflow_hosts)
        self.broker = Broker(copy.deepcopy(policy), monitor)
        self.lock = self.broker.lock
        self.healthy = True
        self.values: dict[str, dict] = {}  # ephemeral; sensitive payloads are not persisted
        configuration = dict(
            policy=asdict(policy), endpoints={k: asdict(v) for k, v in adapters.endpoints.items()},
            workspace_identity=list(__import__("os").fstat(adapters.root)[0:3]),
            max_file=adapters.max_file, timeout=adapters.timeout,
            agent_budget=asdict(monitor.per_agent), swarm_budget=asdict(monitor.per_swarm),
            pairs=sorted(share_pairs), topics=sorted(topics), workflows=sorted(workflow_hosts),
            endpoint_grants={k: sorted(v) for k, v in self.endpoint_grants.items()},
            baseline=capability_only, version=policy_version, swarm=swarm, run=run)
        # Dataclasses include frozensets/enum values. Stable configuration digest.
        encoded = json.dumps(configuration, sort_keys=True,
                             default=lambda x: sorted(x) if isinstance(x, (set, frozenset)) else str(x))
        self.configuration = hashlib.sha256(encoded.encode()).hexdigest()
        state = store.load()
        if state is None:
            self.state = dict(configuration=self.configuration, run=run, swarm=swarm,
                              requests={}, handles={}, contexts={}, files={}, next_action=1,
                              monitor=monitor.snapshot())
            self._commit(dict(event="run-created"))
        else:
            signature = state.pop("signature", "")
            expected = hmac.new(self.key, canonical(state).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("security state signature invalid")
            if state["configuration"] != self.configuration:
                raise ValueError("database belongs to a different run or policy; explicit migration required")
            self.state = state
            monitor.restore(state["monitor"])
            pending = [v for v in state["requests"].values() if v["status"] == "pending"]
            for record in pending:
                record["status"] = "uncertain"
                record["response"] = self.denied("execution-uncertain", status="uncertain")
            if pending:
                monitor.quarantined = True
                self._commit(dict(event="restart-reconciliation", uncertain=len(pending)))

    @staticmethod
    def denied(rule, **fields):
        return dict(allow=False, rule=rule, **fields)

    def authenticate(self, token: str) -> Identity:
        if not isinstance(token, str):
            raise Rejected("authentication")
        digest = hashlib.sha256(token.encode()).digest()
        # Constant-time compare even for unknown tokens; no credential values in exceptions.
        for expected, identity in self.credentials.items():
            if hmac.compare_digest(digest, expected):
                return identity
        raise Rejected("authentication")

    def _commit(self, event):
        if ((event.get("event") == "denial" and
             (self.broker.monitor.quarantined or self.broker.monitor.killed)) or
                event.get("status") == "uncertain" or event.get("event") == "restart-reconciliation"):
            self.state["active_incident"] = self.store.db.execute(
                "SELECT COALESCE(max(seq),0)+1 FROM audit").fetchone()[0]
        self.state["monitor"] = self.broker.monitor.snapshot()
        self.state.pop("signature", None)
        self.state["signature"] = hmac.new(self.key, canonical(self.state).encode(), hashlib.sha256).hexdigest()
        event = dict(event, run=self.run, swarm=self.swarm, policy_version=self.policy_version)
        try:
            return self.store.commit(self.state, event)
        except Exception:
            self.healthy = False
            self.broker.monitor.quarantined = True
            raise

    def _context(self, name):
        return set(self.state["contexts"].get(name, []))

    def _attach(self, name, taints):
        self.state["contexts"][name] = sorted(self._context(name) | set(taints))

    def _provenance(self, identity, dependencies):
        labels = self._context(identity.name)
        for handle in dependencies:
            record = self.state["handles"].get(handle)
            if record is None or record["run"] != self.run or record["owner"] != identity.name:
                raise Rejected("provenance-handle")
            labels.update(record["taints"])
        return labels

    def _shape(self, body):
        if not isinstance(body, dict) or set(body) - {"agent_id", "request_id", "type", "params", "dependencies"}:
            raise Rejected("request-shape")
        rid = body.get("request_id")
        deps = body.get("dependencies", [])
        if (not isinstance(rid, str) or not 1 <= len(rid) <= 128 or
                not isinstance(deps, list) or len(deps) > 32 or
                not all(isinstance(x, str) and len(x) <= 128 for x in deps) or
                not isinstance(body.get("params", {}), dict)):
            raise Rejected("request-shape")
        try:
            kind = ActionType(body.get("type"))
        except (ValueError, TypeError):
            raise Rejected("execution-disabled") from None
        return rid, kind, deps

    def execute(self, token: str, body: dict) -> dict:
        start = time.monotonic()
        body = copy.deepcopy(body)
        try:
            identity = self.authenticate(token)
        except Rejected as exc:
            return self.denied(exc.rule)
        if identity.admin:
            return self.denied("agent-role-required")
        with self.lock:
            if not self.healthy:
                return self.denied("storage-unavailable")
            key = None
            try:
                rid, kind, deps = self._shape(body)
                if body.get("agent_id", identity.name) != identity.name:
                    raise Rejected("identity-mismatch")
                encoded = canonical(body)
                if len(encoded.encode()) > 65536:
                    raise Rejected("request-limit")
                fingerprint = hmac.new(self.key, encoded.encode(), hashlib.sha256).hexdigest()
                key = canonical([identity.name, rid])
                previous = self.state["requests"].get(key)
                if previous is not None:
                    if previous["fingerprint"] != fingerprint:
                        raise Rejected("idempotency-conflict")
                    return dict(previous["response"], replay=True)
                p = self.adapters.validate(kind, body.get("params", {}))
                taints = self._provenance(identity, deps)
                if kind == ActionType.FILE_READ:
                    taints.update(self.state["files"].get(p["path"], []))
                if kind in {ActionType.NET_SEND, ActionType.DNS_RESOLVE}:
                    if p["endpoint"] not in self.endpoint_grants.get(identity.name, frozenset()):
                        raise Rejected("endpoint-capability")
                    e = self.adapters.endpoint(p)
                    params = dict(p, host=e.host)
                    # DNS accounting is an upper application allowance, not packet-level metering.
                    reserved = 4096 + (len(self.adapters.wire(p)) if kind == ActionType.NET_SEND else 0)
                elif kind == ActionType.BUS_PUBLISH:
                    if (identity.name, p["recipient"]) not in self.share_pairs or p["topic"] not in self.topics:
                        raise Rejected("bus-scope")
                    params = p
                    reserved = len(canonical(p).encode())
                else:
                    params, reserved = p, 0
                action = ReservedAction(identity.name, kind, params,
                                        id=self.state["next_action"], reserved=reserved)
                self.state["next_action"] += 1
                policy_decision = self.broker.policy.evaluate(action)
                taints.update(policy_decision.taints)
                if self.capability_only:
                    # Controlled evaluation baseline still uses authentication/adapters/durability.
                    decision = policy_decision
                else:
                    policy_decision.taints |= taints
                    decision = self.broker.monitor.review(action, policy_decision)
                taints.update(decision.taints)
                response = dict(allow=decision.allow, rule=decision.rule,
                                status="pending" if decision.allow else "denied")
                record = dict(fingerprint=fingerprint, status=response["status"], response=response,
                              agent=identity.name, request_id=rid, action_id=action.id,
                              type=kind.value, reserved_bytes=reserved, dependencies=deps)
                self.state["requests"][key] = record
                if decision.allow and not self.capability_only:
                    # Attach BEFORE dispatch, so concurrent output cannot outrun a sensitive read.
                    if kind == ActionType.NET_SEND and e.response_sensitive:
                        taints.add("sensitive:http-response")
                    self._attach(identity.name, taints)
                    if kind == ActionType.FILE_WRITE:
                        self.state["files"][p["path"]] = sorted(taints)
                    if kind == ActionType.BUS_PUBLISH:
                        self._attach(p["recipient"], taints)
                self._commit(dict(event="reservation" if decision.allow else "denial",
                                  agent=identity.name, request_id=rid, action_id=action.id,
                                  type=kind.value, rule=decision.rule, allow=decision.allow,
                                  reserved_bytes=reserved, dependencies=deps,
                                  operation_fingerprint=fingerprint))
                if not decision.allow:
                    return dict(response, broker_ms=round((time.monotonic() - start) * 1000, 3))
                broker_ms = round((time.monotonic() - start) * 1000, 3)
            except Rejected as exc:
                try:
                    self._commit(dict(event="rejected", agent=identity.name, rule=exc.rule))
                except Exception:
                    return self.denied("storage-unavailable")
                return self.denied(exc.rule)
            except Exception:
                self.healthy = False
                return self.denied("storage-unavailable")
        # No global lock held over slow effects. This admitted operation may finish
        # after quarantine, but its sensitivity was already propagated and persisted.
        try:
            if kind == ActionType.BUS_PUBLISH:
                result = {"data": p["payload"], "topic": p["topic"], "recipient": p["recipient"]}
            else:
                result = self.adapters.perform(kind, p)
            outcome, rule = "completed", decision.rule
        except Exception as exc:
            result = {}
            # A dispatched effect may be partial even if the adapter raises.
            outcome, rule = "uncertain", exc.rule if isinstance(exc, Rejected) else "adapter-error"
        with self.lock:
            record["status"] = outcome
            out = dict(allow=outcome == "completed", rule=rule, status=outcome,
                       reserved_bytes=reserved, wire_bytes=result.get("wire_bytes"),
                       broker_ms=broker_ms,
                       end_to_end_ms=round((time.monotonic() - start) * 1000, 3))
            if outcome == "completed":
                handle = secrets.token_urlsafe(32)
                owner = p["recipient"] if kind == ActionType.BUS_PUBLISH else identity.name
                self.state["handles"][handle] = dict(owner=owner, run=self.run,
                    taints=sorted(taints), dependencies=deps, action_id=action.id)
                self.values[handle] = copy.deepcopy(result)
                out["handle"] = handle
            else:
                self.broker.monitor.quarantined = True
            record["response"] = dict(out)  # no payload persisted or replayed
            try:
                self._commit(dict(event="completion", agent=identity.name, request_id=rid,
                                  action_id=action.id, status=outcome, rule=rule,
                                  wire_bytes=result.get("wire_bytes"), reserved_bytes=reserved))
            except Exception:
                return self.denied("storage-unavailable", status="uncertain")
            return dict(out, result=result) if outcome == "completed" else out

    def receive(self, token: str, handle: str):
        """Authenticated message/result receipt; values are ephemeral, labels durable."""
        try:
            identity = self.authenticate(token)
            if identity.admin:
                raise Rejected("agent-role-required")
            with self.lock:
                if not self.healthy:
                    return self.denied("storage-unavailable")
                if self.broker.monitor.quarantined or identity.name in self.broker.monitor.killed:
                    return self.denied("swarm-quarantined")
                taints = self._provenance(identity, [handle])
                if handle not in self.values:
                    raise Rejected("result-unavailable")
                if not self.capability_only:
                    self._attach(identity.name, taints)
                self._commit(dict(event="result-received", agent=identity.name, handle=handle))
                return dict(allow=True, rule="result-owner", result=copy.deepcopy(self.values[handle]))
        except Rejected as exc:
            return self.denied(exc.rule)
        except Exception:
            return self.denied("storage-unavailable")

    def resume(self, token: str, reason: str, incident: int):
        try:
            identity = self.authenticate(token)
            if not identity.admin:
                raise Rejected("admin-role-required")
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000 or type(incident) is not int:
                raise Rejected("review-required")
            with self.lock:
                if not self.healthy:
                    return self.denied("storage-unavailable")
                row = self.store.db.execute("SELECT body FROM audit WHERE seq=?", (incident,)).fetchone()
                if (incident != self.state.get("active_incident") or row is None or
                        json.loads(row[0])["event"] not in {"denial", "completion", "restart-reconciliation"}):
                    raise Rejected("incident-invalid")
                if any(r["status"] == "pending" for r in self.state["requests"].values()):
                    raise Rejected("operations-pending")
                # Preserve all budgets, sensitivity, handles and idempotency records.
                self.broker.monitor.quarantined = False
                self.broker.monitor.killed.clear()
                self.state.pop("active_incident", None)
                seq = self._commit(dict(event="admin-resume", administrator=identity.name,
                                        reason=reason, incident=incident))
                return dict(allow=True, rule="admin-resume", audit_seq=seq)
        except Rejected as exc:
            return self.denied(exc.rule)
        except Exception:
            return self.denied("storage-unavailable")

    def checkpoint(self, token: str):
        identity = self.authenticate(token)
        if not identity.admin:
            raise Rejected("admin-role-required")
        with self.lock:
            return self.store.checkpoint(self.key)

    def close(self):
        self.adapters.close()
        self.store.close()
