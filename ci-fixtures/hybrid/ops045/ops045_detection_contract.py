#!/usr/bin/env python3
"""PCFM OPS045: bounded, metadata-only public detection-control evaluation.

The filename T-code is a scenario hint, NOT event-level ground truth.
Raw detections and identifiable event contents are not exported. Baseline
alerts remain preserved in the disposable runner for comparison only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import re
import sys
import uuid

MAX_JSONL = 50_000_000
MAX_LINE = 1_000_000
MAX_ROWS = 50000
TARGET_RULE = "4386b4e0-f268-42a6-b91d-e3bb768976d6"
CASES = {
    "kerberoasting": {
        "technique_hint": "T1558.003",
        "git_blob": "3dae16bd9baa14e58d934cc335d5bdab5c69ae62",
    },
    "asrep_roasting": {
        "technique_hint": "T1558.004",
        "git_blob": "9b34ff50cabf78605368d0e4c1d70f256aa38aab",
    },
}

class Rejected(ValueError):
    pass


def uniq_pairs(pairs):
    out = {}
    for key, val in pairs:
        if key in out:
            raise Rejected("duplicate JSON key")
        out[key] = val
    return out


def read_public_jsonl(path):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_JSONL:
        raise Rejected("oversized JSONL")
    digest = hashlib.sha256()
    counts = {}
    rows = 0
    with path.open("rb") as src:
        for raw in src:
            digest.update(raw)
            if len(raw) > MAX_LINE:
                raise Rejected("oversized JSONL row")
            if not raw.strip():
                continue
            if rows >= MAX_ROWS:
                raise Rejected("too many JSONL rows")
            try:
                obj = json.loads(raw.decode("utf-8"), object_pairs_hook=uniq_pairs)
            except (UnicodeError, ValueError) as exc:
                raise Rejected("invalid JSONL") from exc
            if not isinstance(obj, dict) or not isinstance(obj.get("RuleID"), str):
                raise Rejected("missing rule reference")
            rid = obj["RuleID"]
            try:
                rid = str(uuid.UUID(rid))
            except ValueError as exc:
                raise Rejected("invalid RuleID UUID") from exc
            if not isinstance(obj.get("EvtxFile"), str):
                raise Rejected("missing source file reference")
            if obj["EvtxFile"].replace("\\", "/").rsplit("/", 1)[-1] != "fixture.evtx":
                raise Rejected("unexpected EVTX filename")
            rows += 1
            counts[rid] = counts.get(rid, 0) + 1
    return {"jsonl_sha256": digest.hexdigest(), "baseline_alerts": rows,
            "rule_counts": counts}


def evaluate_case(case_id, observation, sample_git_blob, sample_sha256):
    if case_id not in CASES:
        raise Rejected("unapproved fixture case")
    if sample_git_blob != CASES[case_id]["git_blob"]:
        raise Rejected("unapproved Git blob source")
    if not re.fullmatch(r"[0-9a-f]{64}", sample_sha256):
        raise Rejected("invalid sample digest")
    counts = observation["rule_counts"]
    if any(not isinstance(v, int) or v < 0 for v in counts.values()):
        raise Rejected("invalid alert counts")
    if sum(counts.values()) != observation["baseline_alerts"]:
        raise Rejected("alert counts are inconsistent")
    baseline = observation["baseline_alerts"]
    target = counts.get(TARGET_RULE, 0)
    if case_id == "kerberoasting" and target == 0:
        raise Rejected("positive scenario lost its expected target-rule alert")
    return {
        "case_id": case_id,
        "source_git_blob": sample_git_blob,
        "source_sha256": sample_sha256,
        "filename_technique_hint": CASES[case_id]["technique_hint"],
        "truth_provenance": "PUBLIC_REPOSITORY_FILENAME_ONLY_UNVERIFIED_EVENT_LABELS",
        "hayabusa_jsonl_sha256": observation["jsonl_sha256"],
        "baseline_alerts": baseline,
        "baseline_unique_rule_ids": len(counts),
        "priority_rule_uuid": TARGET_RULE,
        "priority_alerts": target,
        "lower_priority_alerts_still_in_baseline": baseline - target,
        "detection_loss_from_priority_view": 0,
        "cross_technique_rule_seen_review": case_id == "asrep_roasting" and target > 0,
        "event_label_ground_truth_verified": False,
        "case_level_tp_fp_fn_tn_reportable": False,
    }


def confusion_from_confirmed_cases(cases):
    """Only for truly independently confirmed unit-test labels; never infer from filenames."""
    if not cases or any(case.get("label_provenance") != "INDEPENDENTLY_CONFIRMED"
                        or not isinstance(case.get("actual_positive"), bool)
                        or not isinstance(case.get("predicted_positive"), bool)
                        for case in cases):
        return {"status": "UNSCORABLE_MISSING_INDEPENDENT_LABELS",
                "TP": None, "FP": None, "FN": None, "TN": None,
                "precision": None, "recall": None, "false_positive_rate": None}
    result = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for item in cases:
        actual = item["actual_positive"]
        pred = item["predicted_positive"]
        key = "TP" if pred and actual else "FP" if pred else "FN" if actual else "TN"
        result[key] += 1
    def div(n, d):
        return n / d if d else None
    return {"status": "CONFIRMED_LABELS_ONLY", **result,
            "precision": div(result["TP"], result["TP"] + result["FP"]),
            "recall": div(result["TP"], result["TP"] + result["FN"]),
            "false_positive_rate": div(result["FP"], result["FP"] + result["TN"])}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--kerberos-jsonl", required=True)
    ap.add_argument("--asrep-jsonl", required=True)
    ap.add_argument("--kerberos-sha", required=True)
    ap.add_argument("--asrep-sha", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)
    try:
        cases = [
            evaluate_case("kerberoasting", read_public_jsonl(args.kerberos_jsonl),
                          CASES["kerberoasting"]["git_blob"], args.kerberos_sha),
            evaluate_case("asrep_roasting", read_public_jsonl(args.asrep_jsonl),
                          CASES["asrep_roasting"]["git_blob"], args.asrep_sha),
        ]
        metrics = confusion_from_confirmed_cases([
            {"label_provenance": c["truth_provenance"]} for c in cases
        ])
        if metrics["status"] != "UNSCORABLE_MISSING_INDEPENDENT_LABELS":
            raise Rejected("unverified public filenames must never be treated as verified labels")
        receipt = {
            "schema": "pcfm-ops045-public-detection-control-v1",
            "status": "TWO_ATTACK_TECHNIQUE_CONTROLS_NOT_BENIGN_CORPUS",
            "target_rule_uuid": TARGET_RULE,
            "cases": cases,
            "confusion_matrix": metrics,
            "original_evtx_modified": False,
            "priority_profile_is_post_analysis_view_only": True,
            "raw_event_details_included": False,
            "production_deployment_authorized": False,
        }
        dest = pathlib.Path(args.output)
        if dest.exists():
            raise Rejected("refusing existing output")
        with dest.open("x", encoding="utf-8", newline="\n") as f:
            json.dump(receipt, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        print("PCFM_OPS045_CONTROLS_PASS cases=2 kerberos_target=%d asrep_target=%d baseline_alerts=%d,%d scoring=BLOCKED_UNVERIFIED_LABELS receipt_sha256=%s" %
              (cases[0]["priority_alerts"], cases[1]["priority_alerts"],
               cases[0]["baseline_alerts"], cases[1]["baseline_alerts"],
               hashlib.sha256(dest.read_bytes()).hexdigest()))
        print("PCFM_OPS045_SCOPE=PUBLIC_ATTACK_SCENARIOS_ONLY_NO_BENIGN_GROUND_TRUTH")
    except (OSError, Rejected) as exc:
        print("PCFM_OPS045_REJECTED: %s" % exc, file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
