#!/usr/bin/env python3
"""Synthetic tests for ENV005: no personal data or private repository input."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from incident_replay import (create_event, event_digest, read_json,
                             sha256, trace, validate_policy, validate_event_shape)

POLICY = {
    "schema": "pcfm-env005-policy-v1",
    "sources": {"handoff": "a"*64},
    "allowed_operations": [{"action": "read-only", "target": "isolated-fixture"}],
}


def sequence():
    source = create_event(
        1, "s1", "source_snapshot", "external-document", "0"*64,
        target="handoff", payload_sha256="a"*64)
    request = create_event(
        2, "r1", "operation_request", "verified_operator_claim",
        source["record_hash"], parent_id="s1", action="read-only",
        target="isolated-fixture", time_utc="2026-11-22T00:00:01Z")
    result = create_event(
        3, "x1", "operation_result", "github-api-observation",
        request["record_hash"], parent_id="r1", action="read-only",
        target="isolated-fixture", time_utc="2026-11-22T00:00:02Z")
    return [source, request, result]


def recalc_chain(events):
    prev = "0"*64
    for e in events:
        e["prev_hash"] = prev
        e["record_hash"] = event_digest(e)
        prev = e["record_hash"]
    return events


def anchor(events, policy=POLICY):
    return {"policy_sha256": sha256(policy),
            "last_record_hash": events[-1]["record_hash"]}


class ReplayTests(unittest.TestCase):
    def test_01_benign_internal_only(self):
        r = trace(POLICY, sequence())
        self.assertEqual("INTERNAL_CONSISTENCY_ONLY", r["decision"])
        self.assertFalse(r["anchor_identity_authenticated"])

    def test_02_benign_anchor_not_identity(self):
        e = sequence()
        r = trace(POLICY, e, anchor(e))
        self.assertIsNone(r["first_observed_divergence"])
        self.assertTrue(r["anchor_provided"])
        self.assertFalse(r["anchor_identity_authenticated"])

    def test_03_modified_document_first(self):
        e = sequence()
        e[0]["payload_sha256"] = "b"*64
        recalc_chain(e)
        r = trace(POLICY, e)
        self.assertEqual("UNEXPECTED_SOURCE", r["first_observed_divergence"]["rule"])
        self.assertEqual("s1", r["first_observed_divergence"]["event_id"])

    def test_04_forbidden_private_ci_request(self):
        e = sequence()[:1]
        e.append(create_event(
            2, "r2", "operation_request", "verified_operator_claim",
            e[-1]["record_hash"], action="private-ci-failure-investigation",
            target="private-repo", parent_id="s1",
            time_utc="2026-11-22T00:00:01Z"))
        r = trace(POLICY, e)
        self.assertEqual("UNAUTHORIZED_REQUEST", r["alerts"][0]["rule"])
        self.assertEqual(["s1", "r2"], r["causal_reference_path"])

    def test_05_untrusted_origin(self):
        e = sequence()
        e[1]["origin"] = "attacker-controlled-tool-response"
        recalc_chain(e)
        r = trace(POLICY, e)
        self.assertEqual("UNAUTHORIZED_REQUEST", r["alerts"][0]["rule"])

    def test_06_unauthorized_execution(self):
        e = sequence()
        e[2]["parent_id"] = "s1"
        recalc_chain(e)
        self.assertEqual("UNAUTHORIZED_EXECUTION", trace(POLICY, e)["alerts"][0]["rule"])

    def test_07_log_gap_event(self):
        e = sequence()[:1]
        e.append(create_event(
            2, "gap", "log_gap", "collector",
            e[-1]["record_hash"], time_utc="2026-11-22T00:00:01Z"))
        self.assertEqual("LOG_GAP", trace(POLICY, e)["alerts"][0]["rule"])

    def test_08_digest_mutation_detected(self):
        e = sequence()
        e[0]["action"] = "mutated"
        r = trace(POLICY, e)
        self.assertEqual("RECORD_HASH_MISMATCH", r["alerts"][0]["rule"])

    def test_09_chain_break(self):
        e = sequence()
        e[1]["prev_hash"] = "b"*64
        r = trace(POLICY, e)
        self.assertIn("CHAIN_BREAK", [x["rule"] for x in r["alerts"]])

    def test_10_timestamp_regression(self):
        e = sequence()
        e[1]["time_utc"] = "2026-11-21T23:59:59Z"
        recalc_chain(e)
        self.assertEqual("TIME_REGRESSION", trace(POLICY, e)["alerts"][0]["rule"])

    def test_11_unknown_parent(self):
        e = sequence()
        e[1]["parent_id"] = "forged"
        recalc_chain(e)
        self.assertEqual("UNRESOLVED_PARENT", trace(POLICY, e)["alerts"][0]["rule"])

    def test_12_detached_anchor_detects_full_rehash(self):
        e = sequence()
        old = anchor(e)
        e[0]["payload_sha256"] = "b"*64
        recalc_chain(e)
        rules = {x["rule"] for x in trace(POLICY, e, old)["alerts"]}
        self.assertIn("UNEXPECTED_SOURCE", rules)
        self.assertIn("ANCHOR_MISMATCH", rules)

    def test_13_detached_anchor_detects_policy_change(self):
        e = sequence()
        old = anchor(e)
        p = copy.deepcopy(POLICY)
        p["allowed_operations"].append({"action": "write-file", "target": "main"})
        rules = {x["rule"] for x in trace(p, e, old)["alerts"]}
        self.assertIn("ANCHOR_MISMATCH", rules)

    def test_14_recompute_without_anchor_not_independently_verifiable(self):
        e = sequence()
        p = copy.deepcopy(POLICY)
        p["sources"]["handoff"] = "c"*64
        e[0]["payload_sha256"] = "c"*64
        recalc_chain(e)
        r = trace(p, e)
        self.assertEqual("INTERNAL_CONSISTENCY_ONLY", r["decision"])
        self.assertFalse(r["anchor_provided"])

    def test_15_duplicate_event_id(self):
        e = sequence()
        e[2]["event_id"] = "r1"
        recalc_chain(e)
        self.assertEqual("DUPLICATE_EVENT_ID", trace(POLICY, e)["alerts"][0]["rule"])

    def test_16_duplicate_json_key_fails(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td, "bad.json")
            p.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                read_json(p)

    def test_17_nan_json_fails(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td, "bad.json")
            p.write_text('{"a":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid JSON constant"):
                read_json(p)

    def test_18_bool_sequence_fails(self):
        e = sequence()
        e[0]["seq"] = True
        with self.assertRaisesRegex(ValueError, "invalid seq"):
            trace(POLICY, e)

    def test_19_malformed_policy_fails(self):
        bad = copy.deepcopy(POLICY)
        bad["allowed_operations"][0]["danger"] = True
        with self.assertRaisesRegex(ValueError, "malformed operation"):
            validate_policy(bad)

    def test_20_noncanonical_timestamp_fails(self):
        e = sequence()
        e[0]["time_utc"] = "2026-11-22T09:00:00+09:00"
        with self.assertRaisesRegex(ValueError, "noncanonical UTC"):
            validate_event_shape(e[0])

    def test_21_wrong_anchor_format_fails(self):
        with self.assertRaisesRegex(ValueError, "invalid detached anchor"):
            trace(POLICY, sequence(), {"policy_sha256": "a"*64})

    def test_22_late_alert_parent_path(self):
        e = sequence()
        e[2]["parent_id"] = "s1"
        recalc_chain(e)
        r = trace(POLICY, e)
        self.assertEqual(["s1", "x1"], r["causal_reference_path"])
        self.assertEqual(3, r["first_observed_divergence"]["seq"])

    def test_23_excessive_events_fails(self):
        e = sequence()
        with self.assertRaisesRegex(ValueError, "1..1000"):
            trace(POLICY, e * 400)

    def test_25_sequence_gap_is_an_alert_with_event_id(self):
        e = sequence()
        e[1]["seq"] = 5
        recalc_chain(e)
        r = trace(POLICY, e)
        self.assertEqual("SEQUENCE_GAP", r["first_observed_divergence"]["rule"])
        self.assertEqual("r1", r["first_observed_divergence"]["event_id"])

    def test_26_matching_operator_claim_is_not_identity_proof(self):
        e = sequence()
        r = trace(POLICY, e, anchor(e))
        self.assertEqual("INTERNAL_CONSISTENCY_ONLY", r["decision"])
        self.assertFalse(r["anchor_identity_authenticated"])
        self.assertTrue(any("untrusted event text" in x
                            for x in r["evidence_limitations"]))

    def test_24_missing_record_fails(self):
        with self.assertRaisesRegex(ValueError, "event schema mismatch"):
            e = sequence()
            e[0].pop("origin")
            trace(POLICY, e)


if __name__ == "__main__":
    unittest.main()
