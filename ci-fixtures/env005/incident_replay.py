#!/usr/bin/env python3
"""ENV005: offline first-observed-divergence tracer.

Synthetic / public metadata only. An attacker who can edit both the input log
and the policy or the detached anchor can fabricate a consistent history.
This program does not authenticate a human or instrument ChatGPT internals.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIME_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
EVENT_KEYS = {
    "seq", "event_id", "time_utc", "kind", "origin", "payload_sha256",
    "prev_hash", "parent_id", "action", "target", "record_hash"
}
KINDS = {"source_snapshot", "operation_request", "operation_result", "log_gap"}
ALERT_TYPES = {
    "UNEXPECTED_SOURCE", "UNAUTHORIZED_REQUEST", "UNAUTHORIZED_EXECUTION",
    "LOG_GAP", "RECORD_HASH_MISMATCH", "CHAIN_BREAK", "SEQUENCE_GAP",
    "TIME_REGRESSION", "DUPLICATE_EVENT_ID", "UNRESOLVED_PARENT",
    "ANCHOR_MISMATCH"
}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def sha256(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def unique_pairs(pairs):
    d = {}
    for key, value in pairs:
        if key in d:
            raise ValueError("duplicate JSON key: " + key)
        d[key] = value
    return d


def read_json(path, max_bytes=1_000_000):
    p = Path(path)
    if p.stat().st_size > max_bytes:
        raise ValueError("oversized JSON")
    with p.open("r", encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=unique_pairs,
                         parse_constant=lambda x: (_ for _ in ()).throw(
                             ValueError("invalid JSON constant")))


def hex_digest(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def require(condition, why):
    if not condition:
        raise ValueError(why)


def validate_policy(policy):
    require(isinstance(policy, dict), "policy must be object")
    require(set(policy) == {"schema", "sources", "allowed_operations"},
            "policy schema mismatch")
    require(policy["schema"] == "pcfm-env005-policy-v1", "wrong policy version")
    sources = policy["sources"]
    require(isinstance(sources, dict) and len(sources) <= 200,
            "invalid sources")
    for name, value in sources.items():
        require(isinstance(name, str) and 1 <= len(name) <= 200
                and hex_digest(value), "invalid source digest")
    ops = policy["allowed_operations"]
    require(isinstance(ops, list) and len(ops) <= 200, "invalid operations")
    normalized = []
    for op in ops:
        require(isinstance(op, dict) and set(op) == {"action", "target"},
                "malformed operation")
        require(all(isinstance(v, str) and 1 <= len(v) <= 120
                    for v in op.values()), "invalid operation fields")
        normalized.append((op["action"], op["target"]))
    require(len(normalized) == len(set(normalized)), "duplicate operation")
    return set(normalized)


def validate_event_shape(e):
    require(isinstance(e, dict) and set(e) == EVENT_KEYS, "event schema mismatch")
    require(type(e["seq"]) is int and 1 <= e["seq"] <= 1000000, "invalid seq")
    for field in ("event_id", "origin", "kind"):
        require(isinstance(e[field], str) and 1 <= len(e[field]) <= 120,
                "invalid " + field)
    require(e["kind"] in KINDS, "unknown event kind")
    for field in ("payload_sha256", "prev_hash", "record_hash"):
        require(hex_digest(e[field]), "invalid " + field)
    for field in ("action", "target"):
        require(isinstance(e[field], str) and len(e[field]) <= 200,
                "invalid " + field)
    require(e["parent_id"] is None or
            (isinstance(e["parent_id"], str) and
             1 <= len(e["parent_id"]) <= 120), "invalid parent_id")
    require(isinstance(e["time_utc"], str) and TIME_UTC.fullmatch(e["time_utc"]),
            "noncanonical UTC time")
    parsed = dt.datetime.strptime(e["time_utc"], "%Y-%m-%dT%H:%M:%SZ")
    return parsed.replace(tzinfo=dt.timezone.utc)


def event_digest(event):
    return sha256({key: value for key, value in event.items()
                   if key != "record_hash"})


def create_event(seq, event_id, kind, origin, prev_hash,
                 time_utc="2026-11-22T00:00:00Z", parent_id=None,
                 action="", target="", payload_sha256=None):
    event = {
        "seq": seq, "event_id": event_id, "kind": kind, "origin": origin,
        "time_utc": time_utc, "parent_id": parent_id, "action": action,
        "target": target, "payload_sha256": payload_sha256 or "0"*64,
        "prev_hash": prev_hash
    }
    event["record_hash"] = event_digest(event)
    return event


def trace(policy, events, anchor=None):
    allowed = validate_policy(policy)
    require(isinstance(events, list) and 0 < len(events) <= 1000,
            "events must contain 1..1000 records")
    alerts = []
    event_index = {}
    policy_matching_requests = set()
    prev = "0"*64
    prev_time = None

    def alert(event, rule, detail):
        require(rule in ALERT_TYPES, "invalid internal rule")
        alerts.append({"event_id": event["event_id"], "seq": event["seq"],
                       "rule": rule, "detail": detail})

    for n, event in enumerate(events, 1):
        stamp = validate_event_shape(event)
        if event["seq"] != n:
            alert(event, "SEQUENCE_GAP", "sequence position differs from observed position")
        if event["event_id"] in event_index:
            alert(event, "DUPLICATE_EVENT_ID", "repeated event identifier")
        if event["prev_hash"] != prev:
            alert(event, "CHAIN_BREAK", "previous record hash mismatch")
        if event_digest(event) != event["record_hash"]:
            alert(event, "RECORD_HASH_MISMATCH", "record content digest mismatch")
        if prev_time is not None and stamp < prev_time:
            alert(event, "TIME_REGRESSION", "UTC timestamp order changed")
        if event["parent_id"] is not None and event["parent_id"] not in event_index:
            alert(event, "UNRESOLVED_PARENT", "parent event unavailable")
        if event["kind"] == "source_snapshot":
            expected = policy["sources"].get(event["target"])
            if expected is None or expected != event["payload_sha256"]:
                alert(event, "UNEXPECTED_SOURCE",
                      "source not in the policy baseline or digest differs")
        elif event["kind"] == "operation_request":
            pair = (event["action"], event["target"])
            if event["origin"] != "verified_operator_claim" or pair not in allowed:
                alert(event, "UNAUTHORIZED_REQUEST",
                      "operation not authorized by the supplied policy")
            else:
                policy_matching_requests.add(event["event_id"])
        elif event["kind"] == "operation_result":
            if event["parent_id"] not in policy_matching_requests:
                alert(event, "UNAUTHORIZED_EXECUTION",
                      "no preceding policy-matching request in this log")
        elif event["kind"] == "log_gap":
            alert(event, "LOG_GAP", "collector reported missing observations")
        if event["event_id"] not in event_index:
            event_index[event["event_id"]] = event
        prev = event["record_hash"]
        prev_time = stamp

    if anchor is not None:
        require(isinstance(anchor, dict) and
                set(anchor) == {"policy_sha256", "last_record_hash"},
                "invalid detached anchor format")
        require(all(hex_digest(x) for x in anchor.values()),
                "invalid detached anchor digest")
        if anchor["policy_sha256"] != sha256(policy) or anchor["last_record_hash"] != prev:
            last = events[-1]
            alert(last, "ANCHOR_MISMATCH",
                  "policy or last hash diverges from supplied anchor")

    first = min(alerts, key=lambda a: (a["seq"], a["rule"])) if alerts else None
    path = []
    if first is not None:
        event = event_index.get(first["event_id"])
        seen = set()
        while event and event["event_id"] not in seen and len(path) < 50:
            seen.add(event["event_id"])
            path.append(event["event_id"])
            event = event_index.get(event["parent_id"])
        path.reverse()

    return {
        "schema": "pcfm-env005-result-v1",
        "decision": "REVIEW_REQUIRED" if alerts else "INTERNAL_CONSISTENCY_ONLY",
        "policy_sha256": sha256(policy),
        "last_record_hash": prev,
        "anchor_provided": anchor is not None,
        "anchor_identity_authenticated": False,
        "first_observed_divergence": first,
        "causal_reference_path": path,
        "alerts": alerts,
        "evidence_limitations": [
            "Earliest observed anomaly is not necessarily the original attack point.",
            "Parent references are claims, not independently proven causality.",
            "Hashes do not authenticate the human who issued an instruction.",
            "A verified_operator_claim is just untrusted event text, not a verified approval." ,
            "A compromised controller can rewrite policy, logs and anchor together.",
            "No ChatGPT internal model inputs or tool-dispatch events were obtained.",
            "No GitHub/Drive write authorization is conferred by this program."
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--anchor")
    args = parser.parse_args()
    policy = read_json(args.policy)
    events = read_json(args.events)
    anchor = read_json(args.anchor) if args.anchor else None
    result = trace(policy, events, anchor)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    if result["decision"] != "INTERNAL_CONSISTENCY_ONLY":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
