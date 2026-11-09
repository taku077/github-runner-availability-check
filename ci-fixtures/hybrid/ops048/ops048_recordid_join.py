#!/usr/bin/env python3
"""OPS048: link public synthetic EventRecordIDs to Hayabusa output without scoring."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import uuid

EXPECTED = {
    "windows-2022": {
        "sha256": "33a7b4b1e59713a36becfce7ac55a35d2ff33f832d1eb90c0eac08369323d458",
        "record_ids": (5848, 5849),
    },
    "windows-2025": {
        "sha256": "d7de3587fefc2d06023ef6abcd3d02d64cbaf450b03c8f5c0db4c736846ea6d1",
        "record_ids": (3878, 3879),
    },
}
EVENT_SOURCE = "PCFM_OPS047_BENIGN"
MAX_EVTX = 1_048_576
MAX_JSONL = 5_000_000
MAX_LINE = 500_000
MAX_ROWS = 20_000
REPORT = ("TP", "FP", "FN", "TN", "precision", "recall", "false_positive_rate")


class Rejected(ValueError):
    pass


def unique_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise Rejected("duplicate JSON key")
        result[k] = v
    return result


def parse_json(raw):
    try:
        obj = json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected("malformed JSON") from exc
    if not isinstance(obj, dict):
        raise Rejected("JSON object required")
    return obj


def strict_uint(v):
    if type(v) is int and v >= 0:
        return v
    if type(v) is str and re.fullmatch(r"0|[1-9][0-9]*", v):
        return int(v)
    raise Rejected("invalid integer identifier")


def digest_file(path, max_size):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_size:
        raise Rejected("missing, symlink, or oversized file")
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size


def verify_unadjudicated_truth(receipt):
    # OPS047's actual serialized key. Missing or truthy values must fail closed.
    if receipt.get("independent_external_truth_adjudication") is not False:
        raise Rejected("independent truth must be explicitly unverified")


def validate_source(case_id, folder):
    if case_id not in EXPECTED:
        raise Rejected("unrecognized source case")
    folder = pathlib.Path(folder)
    receipt_path = folder / "receipt.json"
    evtx_path = folder / "controlled-application.evtx"
    rh, size = digest_file(receipt_path, 200_000)
    receipt = parse_json(receipt_path.read_bytes().decode("utf-8-sig"))
    sha, nbytes = digest_file(evtx_path, MAX_EVTX)
    with evtx_path.open("rb") as f:
        if f.read(8) != b"ElfFile\x00":
            raise Rejected("invalid native EVTX header")
    expected = EXPECTED[case_id]
    if sha != expected["sha256"] or receipt.get("evtx_sha256") != sha:
        raise Rejected("source SHA256 mismatch")
    if nbytes != 69632 or receipt.get("evtx_bytes") != nbytes:
        raise Rejected("unexpected EVTX byte count")
    if receipt.get("schema") != "pcfm-ops047-native-evtx-preserved-v1":
        raise Rejected("invalid upstream schema")
    if receipt.get("controlled_count") != 2 or receipt.get("source_log") != "Application":
        raise Rejected("unexpected source scope")
    if receipt.get("capture_kind") != "FILTERED_NATIVE_EXPORT_NOT_ORIGINAL_EVENTLOG_SERVICE_DATABASE":
        raise Rejected("unrecognized export semantics")
    if receipt.get("raw_evtx_uploaded") is not True or receipt.get("artifact_copy_reopened_as_evtx") is not True:
        raise Rejected("upstream source custody not confirmed")
    verify_unadjudicated_truth(receipt)
    if receipt.get("detection_engine_run") is not False:
        raise Rejected("unexpected previous analyzer state")
    if any(receipt.get("metrics", {}).get(k, "MISSING") is not None for k in REPORT):
        raise Rejected("source incorrectly asserts detection metrics")
    events = receipt.get("controlled_events")
    if not isinstance(events, list) or len(events) != 2:
        raise Rejected("must be exactly two deliberately generated events")
    ids = []
    for e in events:
        if not isinstance(e, dict) or e.get("label") != "CONTROLLED_BENIGN_ACTION_ONLY":
            raise Rejected("unknown event label scope")
        if e.get("source") != EVENT_SOURCE or e.get("event_id") != 246:
            raise Rejected("unexpected event provider/ID")
        v = strict_uint(e.get("record_id"))
        if not re.fullmatch(r"[0-9a-f]{64}", e.get("marker_sha256", "")):
            raise Rejected("invalid marker digest")
        ids.append(v)
    if tuple(ids) != expected["record_ids"]:
        raise Rejected("unexpected or reordered source RecordIDs")
    return {"case_id": case_id, "source_sha256": sha, "source_bytes": nbytes,
            "receipt_sha256": rh, "record_ids": ids, "evtx_path": evtx_path}


def read_jsonl(path, allowed_record_ids):
    path = pathlib.Path(path)
    sha, nbytes = digest_file(path, MAX_JSONL)
    count = 0
    linked = {}
    with path.open("rb") as f:
        for raw in f:
            if len(raw) > MAX_LINE:
                raise Rejected("oversized JSONL row")
            if not raw.strip():
                continue
            count += 1
            if count > MAX_ROWS:
                raise Rejected("too many rows")
            try:
                obj = parse_json(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise Rejected("invalid UTF-8") from exc
            record_id = strict_uint(obj.get("RecordID"))
            event_id = strict_uint(obj.get("EventID"))
            if record_id not in allowed_record_ids or event_id != 246:
                raise Rejected("detection references an unapproved source event")
            name = obj.get("EvtxFile")
            if not isinstance(name, str) or name.replace("\\", "/").rsplit("/", 1)[-1] != "controlled-application.evtx":
                raise Rejected("detection references an unapproved EVTX")
            rid = obj.get("RuleID")
            if not isinstance(rid, str):
                raise Rejected("RuleID missing")
            try:
                rid = str(uuid.UUID(rid))
            except ValueError as exc:
                raise Rejected("RuleID invalid") from exc
            linked.setdefault(record_id, []).append(rid)
    return {"jsonl_sha256": sha, "jsonl_bytes": nbytes, "detection_records": count,
            "record_ids_with_detections": sorted(linked),
            "distinct_rule_ids": len({r for ids in linked.values() for r in ids}),
            "per_event": [{"record_id": rid, "matching_alert_records": len(linked.get(rid, [])),
                           "distinct_rule_ids": len(set(linked.get(rid, []))),
                           "status": "RULE_MATCH_REVIEW_ONLY" if linked.get(rid) else "NO_MATCH_OBSERVED_NOT_TN"}
                          for rid in sorted(allowed_record_ids)]}


def evaluate(case_data):
    if len(case_data) != 2 or {c["source"]["case_id"] for c in case_data} != set(EXPECTED):
        raise Rejected("exactly two independently verified upstream exports required")
    # Do not collapse detections from multiple rules into case-wide truth labels.
    return {"schema": "pcfm-ops048-source-recordid-linkage-v1",
            "status": "BOUNDED_ANALYZER_OUTPUT_LINKED_NO_PERFORMANCE_SCORING",
            "analyzer": "Hayabusa v4.3.1 pinned SHA256 (see runner script)",
            "cases": case_data,
            "controlled_action_labels": 4,
            "labels_provenance": "SELF_GENERATED_ACTION_AND_NATIVE_EXPORT_IDENTITY_ONLY",
            "external_independent_truth_adjudication": False,
            "all_rules_evaluated_per_profile": "VERBOSE_DEFAULT_RULESET_NOT_A_COMPLETENESS_PROOF",
            "nonmatching_rows_classified_as_true_negatives": False,
            "absence_of_alert_proves_benign": False,
            "raw_evtx_modified": False,
            "raw_evtx_uploaded_in_this_run": False,
            "raw_detections_uploaded": False,
            "metrics": {"status": "UNSCORABLE_NOT_INDEPENDENTLY_LABELED_FULL_POPULATION",
                        **{k: None for k in REPORT}},
            "target_pc_touched": False,
            "production_deployment_authorized": False}


def main(argv=None):
    p = argparse.ArgumentParser()
    for case in EXPECTED:
        p.add_argument("--" + case + "-folder", required=True)
        p.add_argument("--" + case + "-jsonl", required=True)
    p.add_argument("--output", required=True)
    args = vars(p.parse_args(argv))
    try:
        cases = []
        for case in EXPECTED:
            src = validate_source(case, args[case.replace("-", "_") + "_folder"])
            report = read_jsonl(args[case.replace("-", "_") + "_jsonl"], set(src["record_ids"]))
            src.pop("evtx_path")
            cases.append({"source": src, "analysis": report})
        result = evaluate(cases)
        output = pathlib.Path(args["output"])
        if output.exists() or output.is_symlink():
            raise Rejected("never overwrite output")
        with output.open("x", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        print("PCFM_OPS048_EVENT_JOIN_PASS sources=2 labeled_actions=4 detection_records=" +
              ",".join(str(c["analysis"]["detection_records"]) for c in cases) +
              " rates=NOT_SCORED receipt_sha256=" + hashlib.sha256(output.read_bytes()).hexdigest())
    except (OSError, Rejected) as exc:
        print("PCFM_OPS048_REJECTED: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
