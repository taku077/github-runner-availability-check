#!/usr/bin/env python3
"""Fail-closed validation of public Hayabusa verbose JSONL, NOT independent EVTX proof.

Stdlib-only and read-only. Never parses a real user's logs in public CI.
Output has only counts/hashes by default; do not log raw event fields or paths.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys

REQUIRED = frozenset({"Timestamp", "Channel", "EventID", "RecordID", "RuleTitle", "RuleID", "RuleFile", "EvtxFile"})
MAX_FILE_BYTES = 50_000_000
MAX_LINE_BYTES = 1_000_000
MAX_RECORDS = 50_000
KNOWN_MISSING = frozenset({"", "n/a", "N/A", "-", "null"})


class ValidationError(ValueError):
    pass


def unique_object(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise ValidationError("duplicate JSON key")
        obj[key] = val
    return obj


def id_value(value, label):
    if isinstance(value, bool):
        raise ValidationError(f"{label} not an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        result = int(value)
    else:
        raise ValidationError(f"{label} not a nonnegative integer")
    if result < 0 or result > (1 << 64) - 1:
        raise ValidationError(f"{label} out of range")
    return result


def parse_utc(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValidationError("invalid Timestamp")
    try:
        stamp = dt.datetime.fromisoformat(re.sub(r"\s+([+-]\d{2}:\d{2})$", r"\1", value.replace("Z", "+00:00")))
    except ValueError as e:
        raise ValidationError("Timestamp not an ISO8601 date") from e
    if stamp.tzinfo is None or stamp.utcoffset() != dt.timedelta(0):
        raise ValidationError("Timestamp must be UTC with explicit offset")
    return stamp.isoformat()


def validate_rows(path, *, expected_source_sha256, expected_evtx_basename="fixture.evtx"):
    """Return a receipt based on parser-reported record keys, not independent EVTX XML."""
    src = pathlib.Path(path)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_source_sha256):
        raise ValidationError("expected source SHA256 malformed")
    if src.stat().st_size > MAX_FILE_BYTES:
        raise ValidationError("JSONL over byte budget")
    rows = []
    sha = hashlib.sha256()
    with src.open("rb") as stream:
        for raw in stream:
            sha.update(raw)
            if len(raw) > MAX_LINE_BYTES:
                raise ValidationError("JSONL record over line budget")
            if not raw.strip():
                continue
            if len(rows) >= MAX_RECORDS:
                raise ValidationError("JSONL over record budget")
            try:
                obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            except (ValueError, UnicodeError) as e:
                raise ValidationError("invalid JSONL") from e
            if not isinstance(obj, dict):
                raise ValidationError("JSONL row is not an object")
            missing = sorted(REQUIRED - obj.keys())
            if missing:
                raise ValidationError("missing verbose profile fields: " + ",".join(missing))
            if not all(isinstance(obj[k], str) and obj[k].strip() and len(obj[k]) <= 8192
                       for k in ("Channel", "RuleTitle", "EvtxFile", "RuleID", "RuleFile")):
                raise ValidationError("empty/non-string link reference")
            name = obj["EvtxFile"].replace("\\", "/").rsplit("/", 1)[-1]
            if name != expected_evtx_basename:
                raise ValidationError("EvtxFile does not name the pinned input copy")
            event_id = id_value(obj["EventID"], "EventID")
            record_id = id_value(obj["RecordID"], "RecordID")
            rule_id = obj["RuleID"].strip()
            if rule_id in KNOWN_MISSING:
                raise ValidationError("RuleID unavailable: cannot link alert to rule")
            timestamp = parse_utc(obj["Timestamp"])
            # No Details, Computer, user IDs, command lines, IPs or raw EVTX in receipt.
            rows.append({
                "utc": timestamp, "channel": obj["Channel"], "event_id": event_id,
                "record_id": record_id, "rule_id": rule_id,
                "rule_file_basename": obj["RuleFile"].replace("\\", "/").rsplit("/", 1)[-1],
            })
    if not rows:
        raise ValidationError("empty JSONL: no traceable detections")
    canonical = json.dumps(rows, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "pcfm-public-hayabusa-linkage-v1",
        "status": "PARSER_REPORTED_LINKAGE_ONLY",
        "input_sha256": expected_source_sha256,
        "jsonl_sha256": sha.hexdigest(),
        "linkage_sha256": hashlib.sha256(canonical).hexdigest(),
        "records": len(rows),
        "distinct_rules": len({r["rule_id"] for r in rows}),
        "independent_evtx_record_verified": False,
        "true_positive_rate_verified": False,
        "false_positive_rate_verified": False,
        "target_pc_touched": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--jsonl", required=True)
    p.add_argument("--input-sha256", required=True)
    p.add_argument("--report", required=True)
    p.add_argument("--expected-records", type=int, default=0)
    args = p.parse_args(argv)
    try:
        report = validate_rows(args.jsonl, expected_source_sha256=args.input_sha256)
        if args.expected_records and report["records"] != args.expected_records:
            raise ValidationError("unexpected number of output records")
        dst = pathlib.Path(args.report)
        if dst.exists():
            raise ValidationError("receipt already exists, no overwrite permitted")
        with dst.open("x", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        print("PCFM_HYBRID_LINKAGE_PASS records=%d rules=%d linkage_sha256=%s" % (
            report["records"], report["distinct_rules"], report["linkage_sha256"]))
        print("PCFM_HYBRID_LINKAGE_SCOPE=PARSER_REPORTED_ONLY_NOT_INDEPENDENT_SOURCE_VERIFICATION")
    except (OSError, ValidationError) as e:
        print("PCFM_HYBRID_LINKAGE_REJECTED: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
