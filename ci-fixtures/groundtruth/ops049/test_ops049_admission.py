import copy
import pathlib
import tempfile
import unittest
from ops049_admission import EMPTY_JSONL_SHA, KEYS, RECEIPT_SHA, SOURCE, STATUS, Rejected, evaluate, load_source, unique_pairs


def fixture():
    cases=[]
    for name,(evtx,receipt,ids) in SOURCE.items():
        cases.append({
            "source":{"case_id":name,"source_sha256":evtx,"receipt_sha256":receipt,
                      "source_bytes":69632,"record_ids":list(ids)},
            "analysis":{"detection_records":0,"jsonl_sha256":EMPTY_JSONL_SHA,
                        "jsonl_bytes":1,"distinct_rule_ids":0,"record_ids_with_detections":[],
                        "per_event":[{"record_id":rid,"status":"NO_MATCH_OBSERVED_NOT_TN",
                                      "matching_alert_records":0,"distinct_rule_ids":0} for rid in ids]}
        })
    return {
        "schema":"pcfm-ops048-source-recordid-linkage-v1",
        "status":"BOUNDED_ANALYZER_OUTPUT_LINKED_NO_PERFORMANCE_SCORING",
        "labels_provenance":"SELF_GENERATED_ACTION_AND_NATIVE_EXPORT_IDENTITY_ONLY",
        "analyzer":"Hayabusa v4.3.1 pinned SHA256 (see runner script)",
        "all_rules_evaluated_per_profile":"VERBOSE_DEFAULT_RULESET_NOT_A_COMPLETENESS_PROOF",
        "external_independent_truth_adjudication":False,
        "nonmatching_rows_classified_as_true_negatives":False,
        "absence_of_alert_proves_benign":False,
        "raw_evtx_modified":False,"raw_evtx_uploaded_in_this_run":False,
        "raw_detections_uploaded":False,"target_pc_touched":False,
        "production_deployment_authorized":False,"controlled_action_labels":4,
        "metrics":{"status":"UNSCORABLE_NOT_INDEPENDENTLY_LABELED_FULL_POPULATION",
                  **{key:None for key in KEYS}},
        "cases":cases}


class AdmissionContractTests(unittest.TestCase):
    def assert_bad(self, edit):
        x=fixture();edit(x)
        with self.assertRaises(Rejected): evaluate(x)
    def test_valid_shape_does_not_authorize_scoring(self):
        x=evaluate(fixture())
        self.assertEqual(x["status"],STATUS)
        self.assertEqual(x["independently_adjudicated_count"],0)
        self.assertEqual(x["event_count"],4)
        self.assertTrue(x["detection_absence_is_not_true_negative"])
        self.assertTrue(all(x["metrics"][key] is None for key in KEYS))
    def test_modified_evtx_hash(self):
        self.assert_bad(lambda x:x["cases"][0]["source"].update(source_sha256="0"*64))
    def test_modified_upstream_receipt_hash(self):
        self.assert_bad(lambda x:x["cases"][0]["source"].update(receipt_sha256="0"*64))
    def test_modified_record_id(self):
        self.assert_bad(lambda x:x["cases"][0]["source"]["record_ids"].__setitem__(0,999))
    def test_duplicate_record(self):
        self.assert_bad(lambda x:x["cases"][0]["analysis"]["per_event"].__setitem__(1,copy.deepcopy(x["cases"][0]["analysis"]["per_event"][0])))
    def test_duplicate_case(self):
        self.assert_bad(lambda x:x["cases"].__setitem__(1,copy.deepcopy(x["cases"][0])))
    def test_missing_case(self):
        self.assert_bad(lambda x:x["cases"].pop())
    def test_misrepresented_independent_truth(self):
        self.assert_bad(lambda x:x.update(external_independent_truth_adjudication=True))
    def test_missing_independence_disclaimer(self):
        self.assert_bad(lambda x:x.pop("external_independent_truth_adjudication"))
    def test_string_false_not_accepted(self):
        self.assert_bad(lambda x:x.update(external_independent_truth_adjudication="false"))
    def test_absence_not_true_negative(self):
        self.assert_bad(lambda x:x.update(absence_of_alert_proves_benign=True))
    def test_fabricated_true_negatives(self):
        self.assert_bad(lambda x:x["metrics"].update(TN=4))
    def test_fabricated_false_positive_rate(self):
        self.assert_bad(lambda x:x["metrics"].update(false_positive_rate=0))
    def test_source_security_flag(self):
        self.assert_bad(lambda x:x.update(target_pc_touched=True))
    def test_rule_coverage_overclaim(self):
        self.assert_bad(lambda x:x.update(all_rules_evaluated_per_profile="COMPLETE"))
    def test_wrong_analyzer(self):
        self.assert_bad(lambda x:x.update(analyzer="Unpinned"))
    def test_wrong_jsonl_hash(self):
        self.assert_bad(lambda x:x["cases"][1]["analysis"].update(jsonl_sha256="0"*64))
    def test_modified_alert_count(self):
        self.assert_bad(lambda x:x["cases"][1]["analysis"].update(detection_records=2))
    def test_missing_event(self):
        self.assert_bad(lambda x:x["cases"][1]["analysis"]["per_event"].pop())
    def test_event_status_changed_to_tn(self):
        self.assert_bad(lambda x:x["cases"][1]["analysis"]["per_event"][0].update(status="TN"))
    def test_boolean_is_not_record_id(self):
        self.assert_bad(lambda x:x["cases"][0]["analysis"]["per_event"][0].update(record_id=True))
    def test_bad_source_byte_length(self):
        self.assert_bad(lambda x:x["cases"][0]["source"].update(source_bytes=1))
    def test_missing_scoring_key(self):
        self.assert_bad(lambda x:x["metrics"].pop("FN"))
    def test_missing_input_digest_error(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"receipt.json";p.write_text("{}")
            with self.assertRaises(Rejected):load_source(p)
    def test_duplicate_json_keys(self):
        with self.assertRaises(Rejected):unique_pairs([("a",1),("a",2)])
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"receipt.json";p.write_text("{}")
            l=pathlib.Path(d)/"link.json";l.symlink_to(p)
            with self.assertRaises(Rejected):load_source(l)
    def test_pin_has_sha256_length(self):
        self.assertEqual(len(RECEIPT_SHA),64)


if __name__ == "__main__":
    unittest.main()
