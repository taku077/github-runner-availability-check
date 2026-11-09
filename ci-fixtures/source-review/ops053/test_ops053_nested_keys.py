import json
import unittest
from ops053_nested_keys import fresh,inspect_one,ident_type,IDS,Rejected

class StructureTests(unittest.TestCase):
    def result(self,obj):
        x=fresh();inspect_one(obj,x);return x
    def test_nested_system(self):
        x=self.result({"Event":{"System":{"EventRecordID":25,"Computer":"SECRET"}}})
        self.assertEqual(x["EventRecordID"]["nested_hits"],1)
        self.assertEqual(x["EventRecordID"]["inside_system_hits"],1)
    def test_root(self):
        self.assertEqual(self.result({"EventRecordID":3})["EventRecordID"]["top_level_hits"],1)
    def test_list(self):
        self.assertEqual(self.result({"Events":[{"RecordID":"2"}]})["RecordID"]["events_with_key"],1)
    def test_name_case(self):
        self.assertEqual(self.result({"system":{"recordid":8}})["RecordID"]["nested_hits"],1)
    def test_repeated_hit_one_event(self):
        x=self.result({"array":[{"RecordID":1},{"RecordID":2}]})
        self.assertEqual(x["RecordID"]["nested_hits"],2)
        self.assertEqual(x["RecordID"]["events_with_key"],1)
    def test_private_values_never_serialized(self):
        x=self.result({"Computer":"PRIVATE-PC-NAME","RecordID":1000042})
        self.assertNotIn("PRIVATE-PC-NAME",json.dumps(x))
        self.assertNotIn("1000042",json.dumps(x))
    def test_no_broad_key_leak(self):
        self.assertNotIn("secret",json.dumps(self.result({"secret":"SECRET_PERSON"})))
    def test_raw_xml_string_not_parsed(self):
        x=self.result({"RawXml":"<EventRecordID>77</EventRecordID>"})
        self.assertEqual(x["EventRecordID"]["events_with_key"],0)
    def test_event_id_is_not_record_id(self):
        x=self.result({"EventID":4688,"ProcessID":22})
        self.assertEqual(sum(x[k]["events_with_key"] for k in IDS),0)
    def test_bool_not_integer(self):
        self.assertEqual(ident_type(True),"other_or_invalid")
    def test_positive_integer(self):
        self.assertEqual(ident_type(75),"positive_integer")
    def test_decimal_string(self):
        self.assertEqual(ident_type("75"),"decimal_string")
    def test_unicode_decimal_rejected(self):
        self.assertEqual(ident_type("１２３"),"other_or_invalid")
    def test_zero_not_positive(self):
        self.assertEqual(ident_type(0),"other_or_invalid")
    def test_list_root_rejected(self):
        with self.assertRaises(Rejected):inspect_one([],fresh())
    def test_too_deep(self):
        x={"a":5}
        for i in range(25):x={"a":x}
        with self.assertRaises(Rejected):inspect_one(x,fresh())
    def test_node_budget(self):
        x={"array":[{} for i in range(20001)]}
        with self.assertRaises(Rejected):inspect_one(x,fresh())
    def test_sequence_number_not_record_proof(self):
        x=self.result({"SequenceNumber":"101"})
        self.assertEqual(x["SequenceNumber"]["events_with_key"],1)
        self.assertEqual(x["EventRecordID"]["events_with_key"],0)

if __name__=="__main__":unittest.main()
