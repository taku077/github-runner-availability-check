import hashlib
import json
import pathlib
import tempfile
import unittest
from ops045_detection_contract import (
    TARGET_RULE, CASES, Rejected, read_public_jsonl,
    evaluate_case, confusion_from_confirmed_cases,
)

class DetectionControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = pathlib.Path(self.tmp.name) / 'out.jsonl'
        self.row = {'RuleID': TARGET_RULE, 'EvtxFile': '/public/fixture.evtx',
                    'Computer': 'SENSITIVE_STRING_SHOULD_NOT_LEAK',
                    'Details': 'another secret'}
    def put(self, rows):
        self.file.write_bytes(b'\n'.join(json.dumps(r).encode() for r in rows) + b'\n')
        return self.file
    def observation(self, cases=None):
        return read_public_jsonl(self.put(cases if cases is not None else [self.row]))
    def test_read_one(self):
        d = self.observation()
        self.assertEqual(d['baseline_alerts'], 1)
        self.assertEqual(d['rule_counts'][TARGET_RULE], 1)
    def test_target_positive(self):
        d = evaluate_case('kerberoasting', self.observation(), CASES['kerberoasting']['git_blob'], 'a'*64)
        self.assertEqual(d['priority_alerts'], 1)
        self.assertNotIn('SENSITIVE_STRING', json.dumps(d))
        self.assertFalse(d['event_label_ground_truth_verified'])
    def test_second_sample_without_target(self):
        o = {'jsonl_sha256':'a'*64, 'baseline_alerts':0,'rule_counts':{}}
        d = evaluate_case('asrep_roasting', o, CASES['asrep_roasting']['git_blob'], 'b'*64)
        self.assertFalse(d['cross_technique_rule_seen_review'])
        self.assertFalse(d['case_level_tp_fp_fn_tn_reportable'])
    def test_second_sample_with_target_is_review_not_false_positive(self):
        d = evaluate_case('asrep_roasting', self.observation(), CASES['asrep_roasting']['git_blob'], 'b'*64)
        self.assertTrue(d['cross_technique_rule_seen_review'])
        self.assertFalse(d['case_level_tp_fp_fn_tn_reportable'])
    def test_positive_case_no_target_reject(self):
        o = {'jsonl_sha256':'a'*64, 'baseline_alerts':0,'rule_counts':{}}
        with self.assertRaises(Rejected):
            evaluate_case('kerberoasting', o, CASES['kerberoasting']['git_blob'], 'a'*64)
    def test_unpinned_case_reject(self):
        with self.assertRaises(Rejected):
            evaluate_case('another', self.observation(), 'a'*40, 'b'*64)
    def test_wrong_blob_reject(self):
        with self.assertRaises(Rejected):
            evaluate_case('kerberoasting', self.observation(), 'f'*40, 'b'*64)
    def test_duplicate_json_keys_reject(self):
        self.file.write_bytes(b'{"RuleID":"a", "RuleID":"b"}\n')
        with self.assertRaises(Rejected):read_public_jsonl(self.file)
    def test_invalid_json_reject(self):
        self.file.write_bytes(b'{not json}\n')
        with self.assertRaises(Rejected):read_public_jsonl(self.file)
    def test_non_uuid_reject(self):
        with self.assertRaises(Rejected):read_public_jsonl(self.put([dict(self.row, RuleID='fake')]))
    def test_wrong_evtx_name_reject(self):
        with self.assertRaises(Rejected):read_public_jsonl(self.put([dict(self.row, EvtxFile='real_case.evtx')]))
    def test_negative_guard_unlabeled(self):
        out = confusion_from_confirmed_cases([{'label_provenance':'PUBLIC_FILENAME_ONLY', 'actual_positive':False, 'predicted_positive':False}])
        self.assertIsNone(out['TN'])
        self.assertIsNone(out['false_positive_rate'])
    def test_scoring_real_confirmed_inputs_only(self):
        rows=[{'label_provenance':'INDEPENDENTLY_CONFIRMED','actual_positive':a,'predicted_positive':p} for a,p in ((True,True),(True,False),(False,True),(False,False))]
        out=confusion_from_confirmed_cases(rows)
        self.assertEqual((out['TP'],out['FN'],out['FP'],out['TN']), (1,1,1,1))
        self.assertEqual(out['recall'],.5)
        self.assertEqual(out['false_positive_rate'],.5)
    def test_zero_denominator_null(self):
        rows=[{'label_provenance':'INDEPENDENTLY_CONFIRMED','actual_positive':False,'predicted_positive':False}]
        out=confusion_from_confirmed_cases(rows)
        self.assertIsNone(out['precision'])
        self.assertIsNone(out['recall'])
    def test_prioritization_no_loss(self):
        other='4386b4e0-f268-42a6-b91d-e3bb768976d7'
        d=evaluate_case('kerberoasting',self.observation(),CASES['kerberoasting']['git_blob'],'a'*64)
        self.assertEqual(d['detection_loss_from_priority_view'],0)
        self.assertEqual(d['lower_priority_alerts_still_in_baseline'],0)

if __name__=='__main__':
    unittest.main()
