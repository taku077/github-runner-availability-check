"""SEC145 isolated lifecycle/fencing/crash recovery tests; fake keys only."""
import concurrent.futures
import copy
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, signed_fixture
from delivery_lifecycle import Lifecycle, RECOVERY_ACTION, Worker

KEY = b"sec145-only-fake-recovery-key-never-deployed-12345"
SECRET = b"sec145-only-fake-webhook-key-never-deployed"
GUID = "0b989ba4-242f-11e5-81e1-c7b6966d2516"
HEAD = "a" * 40


def payload():
    return {
        "repository": {"full_name": EXPECTED_REPOSITORY},
        "installation": {"id": 123}, "number": 4,
        "pull_request": {"head": {"sha": HEAD}}
    }


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sec145-")
        self.db = Path(self.tmp.name) / "lifecycle.db"
        self.store = Lifecycle(self.db)
        self.event = payload()

    def tearDown(self):
        self.tmp.cleanup()

    def receive(self, *, now=100, event=None, signature=None, store=None):
        raw, good_sig = signed_fixture(self.event if event is None else event, SECRET)
        return (self.store if store is None else store).receive(
            body=raw, signature=good_sig if signature is None else signature,
            secret=SECRET, delivery_id=GUID, event="pull_request", now=now)

    def ticket(self, *, attempt=1, expires=9999, sha=HEAD, digest=None):
        raw, _ = signed_fixture(self.event, SECRET)
        t = {"action": RECOVERY_ACTION, "delivery_id": GUID,
             "payload_sha256": hashlib.sha256(raw).hexdigest()
                if digest is None else digest,
             "head_sha": sha, "attempt": attempt, "expires_at": expires}
        mac = hmac.new(KEY, json.dumps(t, sort_keys=True,
                       separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        return t, mac

    def expired(self):
        self.receive()
        original = self.store.start(GUID, now=100, lease=10)
        self.assertEqual(self.store.hold(GUID, now=110), "RECOVERY_HOLD")
        return original

    def synthetic_rearm(self, t, mac, now=120, alleged_head=HEAD, key=KEY):
        return self.store.synthetic_rearm(
            t, mac, fake_key=key, alleged_live_head=alleged_head, now=now)

    def test_received_does_not_authorize(self):
        x = self.receive()
        self.assertEqual(x["status"], "NEW_RECEIVED")
        self.assertFalse(x["authorized"])
        self.assertFalse(x["check_written"])

    def test_identical_redelivery_is_not_new(self):
        self.receive()
        self.assertEqual(self.receive(now=101)["status"], "ALREADY_RECEIVED")

    def test_redelivery_while_processing_is_not_reclaimed(self):
        self.receive()
        self.store.start(GUID, now=100, lease=10)
        self.assertEqual(self.receive(now=105)["status"], "IN_PROGRESS")

    def test_redelivery_after_completion_does_not_restart(self):
        self.receive()
        w = self.store.start(GUID, now=100)
        self.store.finish_observation(w, now=101)
        self.assertEqual(self.receive(now=102)["status"],
                         "ALREADY_OBSERVED_COMPLETE")

    def test_signed_body_change_same_id_is_collision(self):
        self.receive()
        changed = copy.deepcopy(self.event)
        changed["pull_request"]["head"]["sha"] = "b" * 40
        with self.assertRaisesRegex(Rejected, "collision"):
            self.receive(now=101, event=changed)

    def test_bad_signature_does_not_poison_ledger(self):
        with self.assertRaisesRegex(Rejected, "invalid signature"):
            self.receive(signature="sha256=" + "0"*64)
        self.assertEqual(self.receive()["status"], "NEW_RECEIVED")

    def test_successful_internal_completion_not_external_approval(self):
        self.receive()
        w = self.store.start(GUID, now=100)
        result = self.store.finish_observation(w, now=101)
        self.assertEqual(result["status"], "OBSERVED_COMPLETE_NOT_AUTHORIZED")
        self.assertFalse(result["authorized"])
        self.assertFalse(result["check_written"])

    def test_two_concurrent_workers_cannot_start(self):
        self.receive()
        def begin(_):
            try:
                self.store.start(GUID, now=100)
                return "started"
            except Rejected:
                return "denied"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
            result = list(e.map(begin, (1, 2)))
        self.assertCountEqual(result, ["started", "denied"])

    def test_stale_worker_token_rejected(self):
        self.receive()
        w = self.store.start(GUID, now=100)
        invalid = Worker(GUID, "f" * 48, w.attempt, w.expires)
        with self.assertRaisesRegex(Rejected, "stale worker token"):
            self.store.finish_observation(invalid, now=101)

    def test_wrong_attempt_is_rejected(self):
        self.receive()
        w = self.store.start(GUID, now=100)
        invalid = Worker(GUID, w.token, w.attempt + 1, w.expires)
        with self.assertRaisesRegex(Rejected, "stale worker attempt"):
            self.store.finish_observation(invalid, now=101)

    def test_completion_after_lease_expiry_rejected(self):
        self.receive()
        w = self.store.start(GUID, now=100, lease=10)
        with self.assertRaisesRegex(Rejected, "expired"):
            self.store.finish_observation(w, now=110)

    def test_redelivery_after_deadline_moves_to_hold(self):
        self.receive()
        self.store.start(GUID, now=100, lease=10)
        self.assertEqual(self.receive(now=110)["status"], "RECOVERY_HOLD")
        self.assertEqual(self.receive(now=111)["status"], "RECOVERY_HOLD")

    def test_late_worker_cannot_complete_after_hold(self):
        w = self.expired()
        with self.assertRaisesRegex(Rejected, "stale worker attempt"):
            self.store.finish_observation(w, now=111)

    def test_hold_disallows_automatic_reprocessing(self):
        self.expired()
        with self.assertRaisesRegex(Rejected, "cannot start"):
            self.store.start(GUID, now=111)

    def test_hold_before_expiration_rejected(self):
        self.receive()
        self.store.start(GUID, now=100, lease=10)
        with self.assertRaisesRegex(Rejected, "still active"):
            self.store.hold(GUID, now=105)

    def test_post_restart_timeout_detected(self):
        self.receive()
        self.store.start(GUID, now=100, lease=10)
        reopened = Lifecycle(self.db)
        self.assertEqual(reopened.hold(GUID, now=120), "RECOVERY_HOLD")

    def test_valid_synthetic_rearm_not_authorization(self):
        self.expired()
        t, mac = self.ticket()
        result = self.synthetic_rearm(t, mac)
        self.assertEqual(result["status"], "SYNTHETIC_REARM_NOT_AUTHORIZED")
        self.assertFalse(result["independent_operator_verified"])
        self.assertFalse(result["check_written"])
        self.assertEqual(self.store.status(GUID)["state"], "RECEIVED")

    def test_rearm_old_worker_fenced_by_new_attempt(self):
        old = self.expired()
        t, mac = self.ticket()
        self.synthetic_rearm(t, mac)
        new = self.store.start(GUID, now=121, lease=10)
        self.assertEqual(new.attempt, 2)
        with self.assertRaisesRegex(Rejected, "stale worker attempt"):
            self.store.finish_observation(old, now=122)
        self.store.hold(GUID, now=131)
        with self.assertRaisesRegex(Rejected, "recovery is stale"):
            self.synthetic_rearm(t, mac, now=132)

    def test_wrong_hmac_rearm_rejected(self):
        self.expired()
        t, _ = self.ticket()
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.synthetic_rearm(t, "0"*64)

    def test_expired_ticket_rejected(self):
        self.expired()
        t, mac = self.ticket(expires=119)
        with self.assertRaisesRegex(Rejected, "expired"):
            self.synthetic_rearm(t, mac)

    def test_current_head_changed_rejected(self):
        self.expired()
        t, mac = self.ticket()
        with self.assertRaisesRegex(Rejected, "head mismatch"):
            self.synthetic_rearm(t, mac, alleged_head="c"*40)

    def test_payload_hash_mismatch_rejected(self):
        self.expired()
        t, mac = self.ticket(digest="e"*64)
        with self.assertRaisesRegex(Rejected, "recovery is stale"):
            self.synthetic_rearm(t, mac)

    def test_wrong_synthetic_key_rejected(self):
        self.expired()
        t, mac = self.ticket()
        with self.assertRaisesRegex(Rejected, "HMAC mismatch"):
            self.synthetic_rearm(t, mac, key=b"different-synthetic-key-not-for-production")

    def test_short_recovery_key_rejected(self):
        self.expired()
        t, mac = self.ticket()
        with self.assertRaisesRegex(Rejected, "weak synthetic"):
            self.synthetic_rearm(t, mac, key=b"short")

    def test_clock_rollback_rejected(self):
        self.receive()
        with self.assertRaisesRegex(Rejected, "time rollback"):
            self.receive(now=99)

    def test_nonexistent_record_fails_closed(self):
        with self.assertRaisesRegex(Rejected, "unknown delivery"):
            self.store.status(GUID)

    def test_two_concurrent_ingests_only_one_new(self):
        def insert(_):
            return self.receive()["status"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
            result = list(e.map(insert, (1, 2)))
        self.assertCountEqual(result, ["NEW_RECEIVED", "ALREADY_RECEIVED"])


if __name__ == "__main__":
    unittest.main()
