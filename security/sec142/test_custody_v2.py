"""SEC146 synthetic combined-state SQLite snapshot and restore-preflight tests."""
import copy
import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from custody_v2 import export_custody_snapshot, verify_custody_snapshot
from delivery_lifecycle import Lifecycle, RECOVERY_ACTION
from offline_outbox import OfflineOutbox
from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, signed_fixture

GUID = "0b989ba4-242f-11e5-81e1-c7b6966d2516"
HEAD = "a" * 40
SECRET = b"sec146-fake-webhook-secret-do-not-use"
KEY = b"sec146-only-fake-custody-key-never-for-production"


class CombinedCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sec146-custody-")
        self.root = Path(self.temp.name)
        self.live = self.root / "lifecycle.sqlite"
        self.snapshot = self.root / "snapshot.sqlite"
        self.manifest = self.root / "snapshot.json"
        self.lifecycle = Lifecycle(self.live)
        self.outbox = OfflineOutbox(self.lifecycle)
        self.payload = {
            "repository": {"full_name": EXPECTED_REPOSITORY},
            "installation": {"id": 123}, "number": 4,
            "pull_request": {"head": {"sha": HEAD}}
        }

    def tearDown(self):
        self.temp.cleanup()

    def receive(self):
        body, signature = signed_fixture(self.payload, SECRET)
        self.lifecycle.receive(
            body=body, signature=signature, secret=SECRET,
            delivery_id=GUID, event="pull_request", now=100)

    def complete(self):
        self.receive()
        worker = self.lifecycle.start(GUID, now=101)
        self.lifecycle.finish_observation(worker, now=102)

    def prepare(self):
        return self.outbox.prepare(
            GUID, asserted_head_sha=HEAD, tick=103)["intent_id"]

    def export(self, key=KEY):
        return export_custody_snapshot(
            source_db=self.live, snapshot_db=self.snapshot,
            manifest_file=self.manifest, test_key=key)

    def verify(self, key=KEY, current_db=None):
        return verify_custody_snapshot(
            snapshot_db=self.snapshot, manifest_file=self.manifest,
            test_key=key, current_db=current_db)

    def test_empty_state_tables_backup_all(self):
        result = self.export()
        self.assertEqual(set(result["table_counts"]), {
            "lifecycle", "recovery_audit", "outbox_intents", "outbox_events"
        })
        self.assertTrue(all(count == 0 for count in result["table_counts"].values()))
        self.assertFalse(self.verify()["restored"])

    def test_lifecycle_and_outbox_ledger_are_included(self):
        self.complete()
        self.prepare()
        counts = self.export()["table_counts"]
        self.assertEqual(counts["lifecycle"], 1)
        self.assertEqual(counts["outbox_intents"], 1)
        self.assertEqual(counts["outbox_events"], 1)
        self.verify(current_db=self.live)

    def test_outbox_unknown_response_is_preserved(self):
        self.complete()
        intent = self.prepare()
        self.outbox.mark_uncertain(intent, tick=104)
        self.export()
        self.verify()
        with sqlite3.connect(str(self.snapshot)) as c:
            state = c.execute("SELECT state FROM outbox_intents").fetchone()[0]
        self.assertEqual(state, "UNKNOWN_REMOTE_RESULT")

    def test_recovery_audit_table_is_included(self):
        self.receive()
        self.lifecycle.start(GUID, now=100, lease=10)
        self.lifecycle.hold(GUID, now=110)
        body, _ = signed_fixture(self.payload, SECRET)
        ticket = {"action": RECOVERY_ACTION,
                  "delivery_id": GUID,
                  "payload_sha256": hashlib.sha256(body).hexdigest(),
                  "head_sha": HEAD, "attempt": 1, "expires_at": 999}
        recovery_key = b"fake-sec146-recovery-signature-key-not-real"
        mac = hmac.new(
            recovery_key,
            json.dumps(ticket, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256).hexdigest()
        self.lifecycle.synthetic_rearm(
            ticket, mac, fake_key=recovery_key, alleged_live_head=HEAD, now=120)
        self.assertEqual(self.export()["table_counts"]["recovery_audit"], 1)
        self.verify()

    def test_wrong_key_fails_closed(self):
        self.complete()
        self.export()
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.verify(key=b"wrong-sec146-only-synthetic-hmac-key-123")

    def test_manifest_mutation_fails_closed(self):
        self.complete()
        self.export()
        obj = json.loads(self.manifest.read_text())
        obj["manifest"]["tables"]["lifecycle"]["count"] = 123
        self.manifest.write_text(json.dumps(obj))
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.verify()

    def test_snapshot_byte_tamper_fails_closed(self):
        self.complete()
        self.export()
        with self.snapshot.open("ab") as file:
            file.write(b"changed")
        with self.assertRaisesRegex(Rejected, "SHA mismatch"):
            self.verify()

    def test_new_outbox_intent_makes_old_snapshot_stale(self):
        self.complete()
        self.export()
        self.prepare()
        with self.assertRaisesRegex(Rejected, "current ledger differs"):
            self.verify(current_db=self.live)

    def test_outbox_state_change_makes_snapshot_stale(self):
        self.complete()
        intent = self.prepare()
        self.export()
        self.outbox.mark_uncertain(intent, tick=104)
        with self.assertRaisesRegex(Rejected, "current ledger differs"):
            self.verify(current_db=self.live)

    def test_new_live_event_makes_snapshot_stale(self):
        self.export()
        self.receive()
        with self.assertRaisesRegex(Rejected, "current ledger differs"):
            self.verify(current_db=self.live)

    def test_existing_target_cannot_be_overwritten(self):
        self.complete()
        self.export()
        with self.assertRaisesRegex(Rejected, "pre-existing"):
            self.export()

    def test_existing_manifest_cannot_be_overwritten(self):
        self.manifest.write_text("existing")
        with self.assertRaisesRegex(Rejected, "pre-existing"):
            self.export()

    def test_source_cannot_be_snapshot_target(self):
        with self.assertRaisesRegex(Rejected, "pre-existing"):
            export_custody_snapshot(
                source_db=self.live, snapshot_db=self.live,
                manifest_file=self.manifest, test_key=KEY)

    def test_missing_snapshot_rejected(self):
        self.complete()
        self.export()
        self.snapshot.unlink()  # only synthetic temp file
        with self.assertRaisesRegex(Rejected, "missing or unsafe custody snapshot"):
            self.verify()

    def test_missing_manifest_rejected(self):
        with self.assertRaisesRegex(Rejected, "missing or unsafe custody manifest"):
            self.verify()

    def test_no_snapshot_of_missing_tables(self):
        missing = self.root / "not-lifecycle.sqlite"
        with sqlite3.connect(str(missing)) as c:
            c.execute("CREATE TABLE unrelated(id INTEGER)")
        with self.assertRaisesRegex(Rejected, "missing required"):
            export_custody_snapshot(
                source_db=missing, snapshot_db=self.snapshot,
                manifest_file=self.manifest, test_key=KEY)

    def test_weak_snapshot_key_refused(self):
        with self.assertRaisesRegex(Rejected, "invalid external snapshot key"):
            self.export(key=b"short")

    def test_manifest_does_not_store_secrets_or_worker_tokens(self):
        self.receive()
        worker = self.lifecycle.start(GUID, now=101)
        self.export()
        raw = self.manifest.read_text()
        self.assertNotIn(KEY.decode(), raw)
        self.assertNotIn(SECRET.decode(), raw)
        self.assertNotIn(worker.token, raw)

    def test_verified_copy_remains_internal_only(self):
        self.complete()
        self.prepare()
        self.export()
        result = self.verify(current_db=self.live)
        self.assertFalse(result["check_written"])
        self.assertFalse(result["restored"])
        self.assertFalse(result["external_custody_attested"])
        self.assertEqual(result["independent_enforcement"], "NOT_DEPLOYED")

    def test_unauthorized_manifest_claim_rejected(self):
        self.export()
        envelope = json.loads(self.manifest.read_text())
        envelope["manifest"]["authorized"] = True
        # No key to forge the MAC; user-controlled claim is rejected.
        self.manifest.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
