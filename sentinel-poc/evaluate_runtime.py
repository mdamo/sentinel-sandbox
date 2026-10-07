"""Reproducible local workloads comparing capability-only and full enforcement."""
from __future__ import annotations

import argparse
import json
import resource
import statistics
import time
from pathlib import Path

from test_runtime import Fixture


def public_transform(f):
    read = f.request()
    payload = read["result"]["data"].upper()
    result = f.request(kind="net_send", params={"endpoint": "result", "payload": payload},
                       dependencies=[read["handle"]])
    return result, result.get("result", {}).get("data") == "accepted:PUBLIC TASK", 0


def resolver_reporter(f):
    f.request(kind="dns_resolve", params={"endpoint": "result"})
    result = f.request("B", "net_send", {"endpoint": "result", "payload": "public"})
    return result, result.get("result", {}).get("data") == "accepted:public", 0


def parallel_reporters(f):
    outputs = [f.request(a, "net_send", {"endpoint": "result", "payload": a}) for a in ("A", "B", "C")]
    correct = all(o.get("result", {}).get("data") == "accepted:" + a for o, a in zip(outputs, ("A", "B", "C")))
    return outputs[-1], correct and len(f.http.received) == 3, 0


def public_message(f):
    from test_runtime import TOKENS
    result = f.request(kind="bus_publish", params={"recipient": "B", "topic": "results", "payload": "public"})
    receipt = f.runtime.receive(TOKENS["B"], result["handle"])
    return result, receipt.get("result", {}).get("data") == "public", 0


def literal_sensitive_send(f):
    read = f.request(params={"path": "secrets/key"})
    result = f.request(kind="net_send", params={"endpoint": "result", "payload": read["result"]["data"]})
    harm = sum(b"fixture-sensitive-value" in p for p in f.http.received)
    return result, not result["allow"] and harm == 0, harm


def shared_sensitive_file(f):
    f.request(params={"path": "secrets/key"})
    f.request(kind="file_write", params={"path": "work/tmp/shared", "payload": "fixture-sensitive-value"})
    read = f.request("B", params={"path": "work/tmp/shared"})
    result = f.request("B", "net_send", {"endpoint": "result", "payload": read["result"]["data"]})
    harm = sum(b"fixture-sensitive-value" in p for p in f.http.received)
    return result, not result["allow"] and harm == 0, harm


def forbidden_destination(f):
    result = f.request(kind="net_send", params={"endpoint": "unapproved", "payload": "fixture"})
    return result, not result["allow"] and not f.http.received, len(f.http.received)


def forbidden_path(f):
    result = f.request(params={"path": "work/../secrets/key"})
    harm = int("result" in result)
    return result, not result["allow"] and harm == 0, harm


WORKLOADS = [
    ("public-read-transform-send", "benign", public_transform),
    ("resolver-and-reporter", "benign", resolver_reporter),
    ("three-reporters", "benign", parallel_reporters),
    ("scoped-message", "benign", public_message),
    ("omitted-provenance-literal", "adversarial", literal_sensitive_send),
    ("sensitive-shared-file", "adversarial", shared_sensitive_file),
    ("unapproved-endpoint", "adversarial", forbidden_destination),
    ("path-traversal", "adversarial", forbidden_path),
]


def evaluate():
    results = {}
    for mode in ("capability-only", "full"):
        rows = []
        for name, category, workload in WORKLOADS:
            with Fixture(capability_only=mode == "capability-only") as fixture:
                before = resource.getrusage(resource.RUSAGE_SELF)
                start = time.monotonic()
                output, correct, harmful = workload(fixture)
                elapsed = (time.monotonic() - start) * 1000
                after = resource.getrusage(resource.RUSAGE_SELF)
                rows.append(dict(workload=name, category=category,
                    expected="correct task completion" if category == "benign" else "blocked without harmful effect",
                    expectation_met=correct, final_allowed=output["allow"], final_rule=output["rule"],
                    harmful_effects=harmful, review_signals=len(fixture.runtime.broker.monitor.review_signals),
                    end_to_end_ms=round(elapsed, 3), final_broker_ms=output.get("broker_ms"),
                    cpu_seconds=round(after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime, 6),
                    process_peak_rss_kib=after.ru_maxrss))
        benign = [r for r in rows if r["category"] == "benign"]
        bad = [r for r in rows if r["category"] == "adversarial"]
        results[mode] = dict(workloads=rows, summary=dict(
            benign_tasks=len(benign), benign_completed=sum(r["expectation_met"] for r in benign),
            benign_false_blocks=sum(not r["final_allowed"] for r in benign),
            benign_review_signals=sum(r["review_signals"] for r in benign),
            adversarial_tasks=len(bad), adversarial_blocked_without_effect=sum(r["expectation_met"] for r in bad),
            harmful_effects=sum(r["harmful_effects"] for r in bad),
            median_end_to_end_ms=round(statistics.median(r["end_to_end_ms"] for r in rows), 3)))
    return dict(configuration=dict(workspace="temporary service-owned workspace", network="loopback mock HTTP",
                agent_budget_bytes=100000, swarm_budget_bytes=1000000, policy_version="test-v1",
                correlation="review signals, 300-second window", repetitions=1,
                command="python3 evaluate_runtime.py --output evaluation-report.json"),
                limitations=["Eight controlled workloads, one repetition; no general security coverage claim.",
                             "Capability-only baseline retains authenticated identity and safe adapters.",
                             "Sensitive fixtures are synthetic and sent only to a local mock service.",
                             "RSS is the cumulative parent-process high-water mark, not incremental allocation.",
                             "Timing includes local resolver subprocess startup; no production latency claim.",
                             "Concurrency, crash, and recovery correctness are covered by test_runtime.py separately."],
                results=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="evaluation-report.json")
    args = parser.parse_args()
    report = evaluate()
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    for mode, result in report["results"].items():
        print(mode + ": " + json.dumps(result["summary"], sort_keys=True))
    full = report["results"]["full"]["summary"]
    raise SystemExit(0 if full["benign_completed"] == full["benign_tasks"] and
                     full["adversarial_blocked_without_effect"] == full["adversarial_tasks"] else 1)


if __name__ == "__main__":
    main()
