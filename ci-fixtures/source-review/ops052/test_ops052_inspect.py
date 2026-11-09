import io
import json
import unittest
import zipfile
from ops052_inspect import summarize,git_sha,Rejected
def make(members):
    b=io.BytesIO()
    with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as z:
        for n,blob in members:
            z.writestr(n,blob)
    return b.getvalue()
def check(b):
    return summarize(b,len(b),git_sha(b))
class ArchiveTests(unittest.TestCase):
    def test_normal_jsonlines(self):
        r=check(make([("x.json",b'{"EventID":1,"Channel":"Security","RecordID":8}\n')]))
        self.assertEqual(r["jsonl_event_objects"],1)
        self.assertEqual(r["field_name_presence_counts"]["RecordID"],1)
        self.assertEqual(r["independent_ground_truth_event_count"],0)
        self.assertIsNone(r["metrics"]["TN"])
        self.assertNotIn("x.json",json.dumps(r))
    def test_native_header(self):
        self.assertEqual(check(make([("x.evtx",b"ElfFile\0"+b"\0"*50)]))["native_evtx_members"],1)
    def test_bad_git_sha(self):
        b=make([("x.json",b"{}\n")])
        with self.assertRaises(Rejected):summarize(b,len(b),"0"*40)
    def test_wrong_size(self):
        b=make([("x.json",b"{}\n")])
        with self.assertRaises(Rejected):summarize(b,len(b)+1,git_sha(b))
    def test_zip_slip(self):
        with self.assertRaises(Rejected):check(make([("../evil.json",b"{}\n")]))
    def test_duplicate_member(self):
        with self.assertRaises(Rejected):check(make([("x.json",b"{}\n"),("x.json",b"{}\n")]))
    def test_bad_json(self):
        r=check(make([("x.json",b"{oops}\n")]))
        self.assertIsNone(r["jsonl_event_objects"])
        self.assertEqual(r["json_parse_status"],"INCOMPLETE_NOT_SCORABLE")
    def test_duplicate_json_keys(self):
        r=check(make([("x.json",b'{"a":1,"a":2}\n')]))
        self.assertIn("JSON_DUPLICATE_KEYS_UNVERIFIED",r["json_parse_failure_codes"])
    def test_json_array(self):
        r=check(make([("array.json",b'[{"EventID":1},{"EventID":2}]')]))
        self.assertEqual(r["jsonl_event_objects"],2)
        self.assertEqual(r["json_parse_status"],"COMPLETE")
    def test_invalid_evtx_magic(self):
        with self.assertRaises(Rejected):check(make([("x.evtx",b"NOTEVTX")]))
    def test_unknown_not_assumed_event(self):
        r=check(make([("x.txt",b"random")]))
        self.assertIsNone(r["jsonl_event_objects"])
        self.assertEqual(r["members"][0]["type"],"OTHER_NOT_ANALYZED")
    def test_no_false_positive_rate(self):
        r=check(make([("attack.json",b'{"EventID":1}\n')]))
        self.assertIsNone(r["metrics"]["false_positive_rate"])
        self.assertFalse(r["performance_scoring_admitted"])
    def test_archive_names_not_truth(self):
        r=check(make([("attack.json",b'{"EventID":1}\n')]))
        self.assertFalse(r["attack_event_truth_adjudicated"])
if __name__=="__main__":unittest.main()
