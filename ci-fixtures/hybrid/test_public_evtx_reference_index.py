import json
import pathlib
import tempfile
import unittest

from public_evtx_reference_index import (
    PUBLIC_SAMPLE_SHA256, ValidationError, make_public_index,
)

GOOD = {
    "Timestamp": "2024-01-02 03:04:05.123 +00:00",
    "Channel": "Security",
    "EventID": 4769,
    "RecordID": 123,
    "RuleTitle": "synthetic detection",
    "RuleID": "00000000-0000-4000-8000-000000000001",
    "RuleFile": "example.yml",
    "EvtxFile": "/test/fixture.evtx",
    "Details": "example should not appear in index",
    "Computer": "synthetic-host-should-not-appear",
}


class PublicEVTXIndexTests(unittest.TestCase):
    def fixture(self, obj=None, raw=None):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = pathlib.Path(d.name) / "input.jsonl"
        p.write_bytes(raw if raw is not None else (json.dumps(obj or GOOD) + "\n").encode())
        return p

    def test_minimal_public_fields_only(self):
        result = make_public_index(self.fixture(), PUBLIC_SAMPLE_SHA256)
        self.assertEqual(result["reported_alerts"], 1)
        self.assertEqual(result["event_references"][0]["record_id"], 123)
        self.assertIn("HAYABUSA_REPORTED", result["status"])
        self.assertNotIn("synthetic-host-should-not-appear", json.dumps(result))
        self.assertNotIn("example should not appear", json.dumps(result))
        self.assertNotIn("rule_id", json.dumps(result).lower())

    def test_wrong_source_sha_rejected(self):
        with self.assertRaises(ValidationError):
            make_public_index(self.fixture(), "b" * 64)

    def test_forged_evtx_name_rejected(self):
        data = dict(GOOD, EvtxFile="C:/evidence/private.evtx")
        with self.assertRaises(ValidationError):
            make_public_index(self.fixture(data), PUBLIC_SAMPLE_SHA256)

    def test_no_record_id_rejected(self):
        data = dict(GOOD)
        del data["RecordID"]
        with self.assertRaises(ValidationError):
            make_public_index(self.fixture(data), PUBLIC_SAMPLE_SHA256)

    def test_non_utc_rejected(self):
        data = dict(GOOD, Timestamp="2024-01-02 12:04:05.123 +09:00")
        with self.assertRaises(ValidationError):
            make_public_index(self.fixture(data), PUBLIC_SAMPLE_SHA256)

    def test_duplicate_json_key_rejected(self):
        encoded = json.dumps(GOOD)
        raw = (encoded[:-1] + ',"EventID":1}\n').encode()
        with self.assertRaises(ValidationError):
            make_public_index(self.fixture(raw=raw), PUBLIC_SAMPLE_SHA256)

    def test_deterministic_links(self):
        sample = self.fixture()
        a = make_public_index(sample, PUBLIC_SAMPLE_SHA256)
        b = make_public_index(sample, PUBLIC_SAMPLE_SHA256)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
