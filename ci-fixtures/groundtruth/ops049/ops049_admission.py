#!/usr/bin/env python3
"""OPS049 actual-OPS048 receipt qualification. Scoring is forbidden in this tool."""
import argparse
import hashlib
import json
import pathlib
import sys

RECEIPT_SHA = "22803ace1b7e9b8cb2b0a681759c2775173c3f924e2dfe8aec96ad818d09673b"
SOURCE = {
    "windows-2022": ("33a7b4b1e59713a36becfce7ac55a35d2ff33f832d1eb90c0eac08369323d458",
                     "b80584aa8653c5ffbc0696ee8877941378ae1ff7cc4b2373a23cc2d0066bd75f", (5848, 5849)),
    "windows-2025": ("d7de3587fefc2d06023ef6abcd3d02d64cbaf450b03c8f5c0db4c736846ea6d1",
                     "2af9e2c41f843f0186a0ccbb3a68a8e55a53abea58ca8f31c62accdf31ce90d3", (3878, 3879)),
}
EMPTY_JSONL_SHA = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
KEYS = ("TP", "FP", "FN", "TN", "precision", "recall", "false_positive_rate")
STATUS = "BLOCKED_MISSING_INDEPENDENT_EVENT_TRUTH_AND_POPULATION"


class Rejected(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Rejected(reason)


def unique_pairs(pairs):
    obj = {}
    for k, v in pairs:
        need(k not in obj, "duplicate JSON key")
        obj[k] = v
    return obj


def load_source(path):
    p = pathlib.Path(path)
    need(p.is_file() and not p.is_symlink() and p.stat().st_size <= 100000,
         "invalid input file or size")
    blob = p.read_bytes()
    need(len(blob) == 2178 and hashlib.sha256(blob).hexdigest() == RECEIPT_SHA,
         "OPS048 bytes or fingerprint mismatch")
    try:
        obj = json.loads(blob.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as ex:
        raise Rejected("invalid JSON") from ex
    need(type(obj) is dict, "JSON object expected")
    return obj


def evaluate(r):
    need(r.get("schema") == "pcfm-ops048-source-recordid-linkage-v1",
         "unrecognized receipt schema")
    need(r.get("status") == "BOUNDED_ANALYZER_OUTPUT_LINKED_NO_PERFORMANCE_SCORING",
         "unrecognized analysis status")
    need(r.get("labels_provenance") == "SELF_GENERATED_ACTION_AND_NATIVE_EXPORT_IDENTITY_ONLY",
         "missing self-label caveat")
    need(r.get("analyzer") == "Hayabusa v4.3.1 pinned SHA256 (see runner script)",
         "analyzer identity mismatch")
    need(r.get("all_rules_evaluated_per_profile") ==
         "VERBOSE_DEFAULT_RULESET_NOT_A_COMPLETENESS_PROOF", "rule completeness not known")
    for flag in ("external_independent_truth_adjudication", "nonmatching_rows_classified_as_true_negatives",
                 "absence_of_alert_proves_benign", "raw_evtx_modified",
                 "raw_evtx_uploaded_in_this_run", "raw_detections_uploaded",
                 "target_pc_touched", "production_deployment_authorized"):
        need(r.get(flag) is False, "false-only safety flag: " + flag)
    need(type(r.get("controlled_action_labels")) is int and r["controlled_action_labels"] == 4,
         "unexpected controlled action count")
    m = r.get("metrics")
    need(type(m) is dict and m.get("status") == "UNSCORABLE_NOT_INDEPENDENTLY_LABELED_FULL_POPULATION",
         "metrics state mismatch")
    need(all(k in m and m[k] is None for k in KEYS), "metrics must be null")
    cases = r.get("cases")
    need(type(cases) is list and len(cases) == 2, "two source cases required")
    seen = set()
    events = []
    for item in cases:
        need(type(item) is dict and type(item.get("source")) is dict and
             type(item.get("analysis")) is dict, "case structure invalid")
        src, analysis = item["source"], item["analysis"]
        name = src.get("case_id")
        need(type(name) is str and name in SOURCE and name not in seen, "unapproved/duplicate case")
        seen.add(name)
        evtx_sha, receipt_sha, ids = SOURCE[name]
        need(src.get("source_sha256") == evtx_sha and src.get("receipt_sha256") == receipt_sha
             and type(src.get("source_bytes")) is int and src["source_bytes"] == 69632
             and type(src.get("record_ids")) is list and tuple(src["record_ids"]) == ids,
             "source evidence mismatch")
        need(type(analysis.get("detection_records")) is int and analysis["detection_records"] == 0,
             "unexpected alert count")
        need(analysis.get("jsonl_sha256") == EMPTY_JSONL_SHA
             and type(analysis.get("jsonl_bytes")) is int and analysis["jsonl_bytes"] == 1,
             "JSONL evidence mismatch")
        need(type(analysis.get("distinct_rule_ids")) is int and analysis["distinct_rule_ids"] == 0
             and analysis.get("record_ids_with_detections") == [],
             "unexpected rule detections")
        per = analysis.get("per_event")
        need(type(per) is list and len(per) == 2, "missing per-event audit")
        observed = set()
        for event in per:
            need(type(event) is dict, "malformed per-event record")
            rid = event.get("record_id")
            need(type(rid) is int and rid in ids and rid not in observed,
                 "unrecognized or duplicate EventRecordID")
            observed.add(rid)
            need(event.get("status") == "NO_MATCH_OBSERVED_NOT_TN"
                 and type(event.get("matching_alert_records")) is int
                 and event["matching_alert_records"] == 0
                 and type(event.get("distinct_rule_ids")) is int
                 and event["distinct_rule_ids"] == 0, "event wrongly scored")
            events.append({"source_case": name, "source_evtx_sha256": evtx_sha,
                           "record_id": rid, "alert_records": 0,
                           "adjudicated_truth": "UNKNOWN",
                           "score_status": "NOT_ADMITTED"})
        need(observed == set(ids), "RecordID set incomplete")
    need(seen == set(SOURCE), "missing source case")
    return {
        "schema": "pcfm-ops049-ground-truth-admission-v1",
        "status": STATUS,
        "pinned_input_sha256": RECEIPT_SHA,
        "events": sorted(events, key=lambda x: (x["source_case"], x["record_id"])),
        "event_count": 4,
        "independently_adjudicated_count": 0,
        "reason_codes": [
            "NO_INDEPENDENT_EVENT_LEVEL_TRUTH",
            "NO_EVIDENCE_OF_BLINDED_EXTERNAL_ADJUDICATION",
            "NO_DEFINED_SAMPLING_FRAME_OR_NEGATIVE_DENOMINATOR",
            "NO_VERIFIED_ATTACK_POSITIVE_CONTROLS",
            "NO_ATTESTED_RULE_COVERAGE",
        ],
        "proposed_future_scoring_unit": "DISTINCT_SOURCE_EVENT_NOT_RULE_ALERT_ROW",
        "unknown_events_counted_as_negative": False,
        "detection_absence_is_not_true_negative": True,
        "raw_pc_evidence_included": False,
        "production_deployment_authorized": False,
        "metrics": {"status": "UNSCORABLE", **{key: None for key in KEYS}},
    }


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--input", required=True)
    cli.add_argument("--output", required=True)
    args = cli.parse_args()
    try:
        report = evaluate(load_source(args.input))
        target = pathlib.Path(args.output)
        need(not target.exists() and not target.is_symlink(), "refusing output overwrite")
        with target.open("x", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            f.write("\n")
        print("PCFM_OPS049_ADMISSION_GATE_PASS status=BLOCKED events=4 external_ground_truth=0 metrics=NULL")
        print("PCFM_OPS049_RECEIPT_SHA256=" + hashlib.sha256(target.read_bytes()).hexdigest())
        return 0
    except (OSError, Rejected) as exc:
        print("PCFM_OPS049_REJECTED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
