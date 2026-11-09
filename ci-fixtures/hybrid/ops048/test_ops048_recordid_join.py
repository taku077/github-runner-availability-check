import json
import pathlib
import tempfile
import unittest

from ops048_recordid_join import (
    EXPECTED, Rejected, read_jsonl, evaluate, strict_uint, unique_pairs
)

class RecordLinkageTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.path = pathlib.Path(self.t.name) / "analysis.jsonl"
        self.rid = EXPECTED["windows-2022"]["record_ids"][0]
        self.row = {
            "RuleID": "4386b4e0-f268-42a6-b91d-e3bb768976d6",
            "RecordID": str(self.rid), "EventID": 246,
            "EvtxFile": "/tmp/controlled-application.evtx",
            "Computer": "UNSAFE_MACHINE_NAME", "Details": "PRIVATE_NOT_FOR_OUTPUT",
        }
    def write(self, rows):
        self.path.write_bytes(b"".join((json.dumps(x) + "\n").encode() for x in rows))
        return self.path
    def test_no_detections_is_not_tn(self):
        x=read_jsonl(self.write([]), {self.rid})
        self.assertEqual(x["detection_records"],0)
        self.assertEqual(x["per_event"][0]["status"],"NO_MATCH_OBSERVED_NOT_TN")
    def test_one_match_preserves_anonymity(self):
        x=read_jsonl(self.write([self.row]), {self.rid})
        self.assertEqual(x["detection_records"],1)
        self.assertEqual(x["per_event"][0]["status"],"RULE_MATCH_REVIEW_ONLY")
        self.assertNotIn("PRIVATE_NOT_FOR_OUTPUT",json.dumps(x))
        self.assertNotIn("UNSAFE_MACHINE_NAME",json.dumps(x))
    def test_duplicate_rule_distinguishes_rows(self):
        x=read_jsonl(self.write([self.row,self.row]), {self.rid})
        self.assertEqual((x["detection_records"],x["distinct_rule_ids"]),(2,1))
    def test_unknown_record_rejected(self):
        with self.assertRaises(Rejected):
            read_jsonl(self.write([dict(self.row,RecordID=self.rid+999)]), {self.rid})
    def test_wrong_eid_rejected(self):
        with self.assertRaises(Rejected):
            read_jsonl(self.write([dict(self.row,EventID=4624)]), {self.rid})
    def test_wrong_source_evtx_rejected(self):
        with self.assertRaises(Rejected):
            read_jsonl(self.write([dict(self.row,EvtxFile="private.evtx")]), {self.rid})
    def test_no_uuid_rejected(self):
        with self.assertRaises(Rejected):
            read_jsonl(self.write([dict(self.row,RuleID="fake")]), {self.rid})
    def test_duplicate_json_keys_rejected(self):
        self.path.write_text('{"RecordID":1,"RecordID":2}\n')
        with self.assertRaises(Rejected):
            read_jsonl(self.path,{self.rid})
    def test_boolean_does_not_count_as_numeric_identifier(self):
        with self.assertRaises(Rejected):
            strict_uint(True)
    def test_bad_numeric_string_rejected(self):
        with self.assertRaises(Rejected):
            strict_uint("0005")
    def test_duplicate_pairs_rejected(self):
        with self.assertRaises(Rejected):
            unique_pairs([("a",1),("a",2)])
    def test_global_scoring_always_null(self):
        cases=[{"source":{"case_id":id},"analysis":{"detection_records":0}} for id in EXPECTED]
        out=evaluate(cases)
        self.assertIsNone(out["metrics"]["FP"])
        self.assertIsNone(out["metrics"]["TN"])
        self.assertFalse(out["absence_of_alert_proves_benign"])
    def test_requires_both_sources(self):
        with self.assertRaises(Rejected):
            evaluate([{"source":{"case_id":"windows-2022"}}])

if __name__ == "__main__":
    unittest.main()
