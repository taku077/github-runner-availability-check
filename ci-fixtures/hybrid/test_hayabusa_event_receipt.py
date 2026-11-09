import importlib.util
import pathlib
import tempfile
import unittest
import json

SPEC = importlib.util.spec_from_file_location("receipt", pathlib.Path(__file__).with_name("hayabusa_event_receipt.py"))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
SOURCE_SHA = "a" * 64
GOOD = {
    "Timestamp": "2024-01-02 03:04:05.123 +00:00", "Channel": "Security",
    "EventID": 4769, "RecordID": 123, "RuleTitle": "Fixture Title",
    "RuleID": "f29f0ce0-caae-4daa-b010-000000000000", "RuleFile": "fixture.yml",
    "EvtxFile": "/safe/fixture.evtx", "Computer": "test-host", "Details": "dummy",
}


class ReceiptTests(unittest.TestCase):
    def write(self, lines):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = pathlib.Path(d.name) / "out.jsonl"
        p.write_bytes(b"\n".join(lines) + b"\n")
        return p

    def row(self, **changes):
        o = dict(GOOD)
        o.update(changes)
        return json.dumps(o).encode()

    def test_positive_canonical(self):
        result = module.validate_rows(self.write([self.row()]), expected_source_sha256=SOURCE_SHA)
        self.assertEqual(result["records"], 1)
        self.assertEqual(result["status"], "PARSER_REPORTED_LINKAGE_ONLY")
        self.assertFalse(result["independent_evtx_record_verified"])
        self.assertFalse(result["true_positive_rate_verified"])
        self.assertNotIn("test-host", json.dumps(result))

    def test_missing_fields_rejected(self):
        o = dict(GOOD)
        del o["RuleID"]
        with self.assertRaises(module.ValidationError):
            module.validate_rows(self.write([json.dumps(o).encode()]), expected_source_sha256=SOURCE_SHA)

    def test_duplicate_json_key_rejected(self):
        raw = self.row()[:-1] + b',"RuleID":"shadow"}'
        with self.assertRaises(module.ValidationError):
            module.validate_rows(self.write([raw]), expected_source_sha256=SOURCE_SHA)

    def test_no_rule_rejected(self):
        with self.assertRaises(module.ValidationError):
            module.validate_rows(self.write([self.row(RuleID="n/a")]), expected_source_sha256=SOURCE_SHA)

    def test_wrong_file_rejected(self):
        with self.assertRaises(module.ValidationError):
            module.validate_rows(self.write([self.row(EvtxFile="actual-user.evtx")]), expected_source_sha256=SOURCE_SHA)

    def test_wrong_time_rejected(self):
        for value in ("2024-01-02 03:04:05", "2024-01-02 12:04:05 +09:00", "xyz"):
            with self.subTest(value=value), self.assertRaises(module.ValidationError):
                module.validate_rows(self.write([self.row(Timestamp=value)]), expected_source_sha256=SOURCE_SHA)

    def test_invalid_ids_rejected(self):
        for value in (-1, True, "NaN", 2**64):
            with self.subTest(value=value), self.assertRaises(module.ValidationError):
                module.validate_rows(self.write([self.row(RecordID=value)]), expected_source_sha256=SOURCE_SHA)

    def test_empty_rejected(self):
        with self.assertRaises(module.ValidationError):
            module.validate_rows(self.write([]), expected_source_sha256=SOURCE_SHA)

    def test_size_cap_rejected(self):
        p = self.write([b" " * (module.MAX_LINE_BYTES + 1)])
        with self.assertRaises(module.ValidationError):
            module.validate_rows(p, expected_source_sha256=SOURCE_SHA)

    def test_bad_sha_rejected(self):
        with self.assertRaises(module.ValidationError):
            module.validate_rows(self.write([self.row()]), expected_source_sha256="bad")

    def test_deterministic_receipt(self):
        p = self.write([self.row(), self.row(RecordID=124)])
        a = module.validate_rows(p, expected_source_sha256=SOURCE_SHA)
        b = module.validate_rows(p, expected_source_sha256=SOURCE_SHA)
        self.assertEqual(a, b)


if __name__ == '__main__':
    unittest.main()
