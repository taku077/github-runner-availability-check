"""SEC144 offline synthetic snapshot tests: no GitHub credentials or PC data."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, signed_fixture
from webhook_intake import DeliveryLedger, receive_delivery
from ledger_snapshot import export_snapshot, verify_snapshot

KEY = b"synthetic-snapshot-mac-key-not-real-123"
SECRET = b"synthetic-webhook-secret-not-real-123"
IDS = [
    "0b989ba4-242f-11e5-81e1-c7b6966d2516",
    "0b989ba4-242f-11e5-81e1-c7b6966d2517",
]


class SnapshotRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sec144-")
        self.dir = Path(self.temp.name)
        self.live = self.dir / "live.sqlite3"
        self.snapshot = self.dir / "snapshot.sqlite3"
        self.manifest = self.dir / "snapshot.json"
        self.ledger = DeliveryLedger(self.live)

    def tearDown(self):
        self.temp.cleanup()

    def receive(self, delivery_id=IDS[0]):
        event = {
            "repository": {"full_name": EXPECTED_REPOSITORY},
            "installation": {"id": 12}, "number": 4,
            "pull_request": {"head": {"sha": "a" * 40}},
        }
        body, signature = signed_fixture(event, SECRET)
        return receive_delivery(body=body, signature=signature,
                                secret=SECRET, delivery_id=delivery_id,
                                event_name="pull_request", ledger=self.ledger)

    def make(self):
        return export_snapshot(live_db=self.live, snapshot_db=self.snapshot,
                               manifest_file=self.manifest, external_key=KEY)

    def verify(self, current_db=None, key=KEY):
        return verify_snapshot(snapshot_db=self.snapshot,
                               manifest_file=self.manifest,
                               external_key=key, current_db=current_db)

    def test_empty_ledger_snapshot_verifies_without_authorizing(self):
        r = self.make()
        self.assertEqual(r["delivery_count"], 0)
        self.assertFalse(self.verify()["check_written"])
        self.assertFalse(self.verify()["restored"])

    def test_one_receipt_export_and_readback(self):
        self.receive()
        self.assertEqual(self.make()["delivery_count"], 1)
        self.assertEqual(self.verify()["delivery_count"], 1)

    def test_two_records_including_wal_snapshot(self):
        self.receive(IDS[0])
        self.receive(IDS[1])
        self.assertEqual(self.make()["delivery_count"], 2)
        self.verify(current_db=self.live)

    def test_wrong_mac_key_denied(self):
        self.receive()
        self.make()
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.verify(key=b"wrong-synthetic-key-for-negative-test")

    def test_tampered_manifest_denied(self):
        self.receive()
        self.make()
        obj = json.loads(self.manifest.read_text())
        obj["manifest"]["delivery_count"] = 999
        self.manifest.write_text(json.dumps(obj))
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.verify()

    def test_corrupt_snapshot_bytes_denied(self):
        self.receive()
        self.make()
        with self.snapshot.open("ab") as out:
            out.write(b"tampered")
        with self.assertRaisesRegex(Rejected, "file SHA mismatch"):
            self.verify()

    def test_stale_snapshot_detected_with_live_readback(self):
        self.receive(IDS[0])
        self.make()
        self.receive(IDS[1])
        with self.assertRaisesRegex(Rejected, "live ledger differs"):
            self.verify(current_db=self.live)

    def test_refuses_existing_snapshot(self):
        self.receive()
        self.make()
        with self.assertRaisesRegex(Rejected, "existing snapshot"):
            self.make()

    def test_refuses_existing_manifest(self):
        self.manifest.write_text("preexisting")
        with self.assertRaisesRegex(Rejected, "existing snapshot"):
            self.make()

    def test_missing_snapshot_denied(self):
        self.receive()
        self.make()
        self.snapshot.unlink()  # Only synthetic temp fixture, never original evidence.
        with self.assertRaisesRegex(Rejected, "missing or unsafe snapshot"):
            self.verify()

    def test_missing_live_database_denied(self):
        with self.assertRaisesRegex(Rejected, "missing or unsafe database"):
            export_snapshot(live_db=self.dir / "absent.sqlite",
                            snapshot_db=self.snapshot,
                            manifest_file=self.manifest, external_key=KEY)

    def test_weak_key_denied(self):
        with self.assertRaisesRegex(Rejected, "invalid external verification key"):
            export_snapshot(live_db=self.live, snapshot_db=self.snapshot,
                            manifest_file=self.manifest, external_key=b"short")

    def test_manifest_does_not_disclose_external_key(self):
        self.receive()
        self.make()
        self.assertNotIn(KEY.decode(), self.manifest.read_text())
        self.assertNotIn(SECRET.decode(), self.manifest.read_text())

    def test_offline_recovered_copy_retains_replay_protection(self):
        self.receive()
        self.make()
        self.verify()
        recovered = self.dir / "recovered-copy.sqlite3"
        shutil.copy2(self.snapshot, recovered)  # fixture only; never source overwrite.
        restored_ledger = DeliveryLedger(recovered)
        event = {"repository": {"full_name": EXPECTED_REPOSITORY},
                 "installation": {"id": 12}, "number": 4,
                 "pull_request": {"head": {"sha": "a" * 40}}}
        body, signature = signed_fixture(event, SECRET)
        with self.assertRaisesRegex(Rejected, "duplicate delivery"):
            receive_delivery(body=body, signature=signature, secret=SECRET,
                             delivery_id=IDS[0], event_name="pull_request",
                             ledger=restored_ledger)
        self.assertFalse(self.verify()["restored"])

    def test_live_unchanged_by_snapshot_readback(self):
        self.receive()
        self.make()
        before = self.verify(current_db=self.live)
        after = self.verify(current_db=self.live)
        self.assertEqual(before["rows_sha256"], after["rows_sha256"])

    def test_snapshot_with_wrong_schema_denied(self):
        self.receive()
        self.make()
        obj = json.loads(self.manifest.read_text())
        obj["manifest"]["schema"] = "wrong"
        self.manifest.write_text(json.dumps(obj))
        with self.assertRaisesRegex(Rejected, "wrong snapshot manifest schema"):
            self.verify()

    def test_missing_manifest_denied(self):
        with self.assertRaisesRegex(Rejected, "missing or unsafe manifest"):
            self.verify()

    def test_recovered_copy_not_treated_as_operational_approval(self):
        self.receive()
        self.make()
        r = self.verify()
        self.assertEqual(r["live_merge_enforcement"], "NOT_DEPLOYED")
        self.assertEqual(r["independent_custody"], "NOT_ATTESTED")


if __name__ == "__main__":
    unittest.main()
