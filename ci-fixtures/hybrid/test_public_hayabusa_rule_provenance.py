import json
import pathlib
import tempfile
import unittest
from public_hayabusa_rule_provenance import (
    SAMPLE_SHA, ValidationError, parse_rule_uuid, inventory_rules, verify_rule_provenance
)

RID = "12345678-1234-4123-8123-123456789abc"
GOOD = {
    "Timestamp": "2024-01-02T03:04:05Z",
    "Channel": "Security", "EventID": 4769, "RecordID": 123,
    "RuleTitle": "Synthetic Test", "RuleID": RID, "RuleFile": "test_rule.yml",
    "EvtxFile": "fixture.evtx"
}


class PublicRuleProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.root = self.base / "rules"
        self.root.mkdir()
        self.rule = self.root / "test_rule.yml"
        self.rule.write_text("title: Synthetic Test\nid: " + RID + "\nlevel: high\n", encoding="utf-8")
        self.jsonl = self.base / "alerts.jsonl"
        self.write_alert(GOOD)

    def write_alert(self, data):
        self.jsonl.write_text(json.dumps(data) + "\n", encoding="utf-8")

    def test_matches_rule_id_filename_and_sha(self):
        out = verify_rule_provenance(self.jsonl, self.root)
        self.assertEqual(out["matched_rule_count"], 1)
        self.assertEqual(out["alerts_linked"], 1)
        self.assertFalse(out["rules_semantic_correctness_verified"])
        self.assertNotIn("Details", json.dumps(out))

    def test_unchanged_rule_receipt_reproducible(self):
        self.assertEqual(verify_rule_provenance(self.jsonl, self.root),
                         verify_rule_provenance(self.jsonl, self.root))

    def test_fake_rule_id_rejected(self):
        self.write_alert(dict(GOOD, RuleID="00000000-0000-4000-8000-000000000001"))
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)

    def test_wrong_filename_rejected(self):
        self.write_alert(dict(GOOD, RuleFile="wrong.yml"))
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)

    def test_rule_file_id_mismatch_rejected(self):
        self.rule.write_text("id: 00000000-0000-4000-8000-000000000001\n")
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)

    def test_duplicate_uuid_in_another_rule_rejected(self):
        (self.root / "another.yml").write_text("id: " + RID + "\n")
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)

    def test_rule_file_tamper_changes_digest(self):
        a = verify_rule_provenance(self.jsonl, self.root)
        self.rule.write_text(self.rule.read_text() + "description: changed\n")
        b = verify_rule_provenance(self.jsonl, self.root)
        self.assertNotEqual(a["matched_rules"][0]["sha256"], b["matched_rules"][0]["sha256"])
        self.assertNotEqual(a["rule_inventory_sha256"], b["rule_inventory_sha256"])

    def test_invalid_rule_uuid_rejected(self):
        self.write_alert(dict(GOOD, RuleID="not-a-uuid"))
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)

    def test_duplicate_json_key_rejected(self):
        raw = json.dumps(GOOD)
        self.jsonl.write_text(raw[:-1] + ',"RuleID":"shadow"}\n')
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)

    def test_wrong_sample_digest_rejected(self):
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root, source_sha="f" * 64)

    def test_rules_dir_must_be_named_rules(self):
        with self.assertRaises(ValidationError):
            inventory_rules(self.base)

    def test_invalid_multi_id_not_indexed(self):
        self.rule.write_text("id: " + RID + "\nid: 00000000-0000-4000-8000-000000000001\n")
        with self.assertRaises(ValidationError):
            verify_rule_provenance(self.jsonl, self.root)


if __name__ == "__main__":
    unittest.main()
