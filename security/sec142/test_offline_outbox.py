"""SEC146 offline outbox negative tests. No GitHub API requests or real keys."""
import concurrent.futures
import tempfile
import unittest
from pathlib import Path

from delivery_lifecycle import Lifecycle
from offline_outbox import OfflineOutbox
from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, signed_fixture

GUID = "0b989ba4-242f-11e5-81e1-c7b6966d2516"
HEAD = "a" * 40
SECRET = b"sec146-synthetic-webhook-secret-never-deploy"
REPO = EXPECTED_REPOSITORY


class OfflineOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sec146-outbox-")
        self.db = Path(self.temp.name) / "lifecycle.db"
        self.life = Lifecycle(self.db)
        self.outbox = OfflineOutbox(self.life)

    def tearDown(self):
        self.temp.cleanup()

    def ingest(self):
        payload = {"repository": {"full_name": REPO},
                   "installation": {"id": 123}, "number": 4,
                   "pull_request": {"head": {"sha": HEAD}}}
        raw, sig = signed_fixture(payload, SECRET)
        self.life.receive(body=raw, signature=sig, secret=SECRET,
                          delivery_id=GUID, event="pull_request", now=100)

    def observe(self):
        self.ingest()
        worker = self.life.start(GUID, now=101)
        self.life.finish_observation(worker, now=102)

    def prepare(self, tick=103, sha=HEAD):
        return self.outbox.prepare(GUID, asserted_head_sha=sha, tick=tick)

    def sample(self, intent):
        return {"head_sha": HEAD, "app_id": 1234,
                "external_id": intent, "check_id": 789,
                "conclusion": "neutral"}

    def test_unobserved_delivery_cannot_queue(self):
        self.ingest()
        with self.assertRaisesRegex(Rejected, "observation not completed"):
            self.prepare()

    def test_prepared_is_local_only(self):
        self.observe()
        r = self.prepare()
        self.assertEqual(r["status"], "PREPARED_LOCAL_ONLY")
        self.assertFalse(r["check_written"])
        self.assertFalse(r["real_github_api_called"])
        self.assertEqual(r["authorization"], "NONE")

    def test_idempotent_prepare_same_sha(self):
        self.observe()
        x = self.prepare()
        y = self.prepare(tick=104)
        self.assertEqual(x, y)

    def test_idempotent_across_restart(self):
        self.observe()
        x = self.prepare()
        other = OfflineOutbox(Lifecycle(self.db))
        y = other.prepare(GUID, asserted_head_sha=HEAD, tick=104)
        self.assertEqual(x["intent_id"], y["intent_id"])

    def test_wrong_pr_head_denied(self):
        self.observe()
        with self.assertRaisesRegex(Rejected, "stale candidate"):
            self.prepare(sha="b" * 40)

    def test_malformed_sha_denied(self):
        self.observe()
        with self.assertRaisesRegex(Rejected, "invalid intent"):
            self.prepare(sha="garbage")

    def test_prepare_clock_rollback_denied(self):
        self.observe()
        with self.assertRaisesRegex(Rejected, "clock rollback"):
            self.prepare(tick=100)

    def test_uncertain_response_not_retried(self):
        self.observe()
        i = self.prepare()["intent_id"]
        r = self.outbox.mark_uncertain(i, tick=104)
        self.assertEqual(r["status"], "UNKNOWN_REMOTE_RESULT")
        with self.assertRaisesRegex(Rejected, "transition denied"):
            self.outbox.mark_uncertain(i, tick=105)
        self.assertEqual(self.prepare(tick=106)["status"],
                         "UNKNOWN_REMOTE_RESULT")

    def test_uncertain_after_restart_persists(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        fresh = OfflineOutbox(Lifecycle(self.db))
        self.assertEqual(fresh.status(i)["status"], "UNKNOWN_REMOTE_RESULT")

    def test_cancel_before_send_does_not_return_to_prepared(self):
        self.observe()
        i = self.prepare()["intent_id"]
        r = self.outbox.cancel_before_sending(i, tick=104)
        self.assertEqual(r["status"], "CANCELLED_WITHOUT_SEND")
        with self.assertRaisesRegex(Rejected, "transition denied"):
            self.outbox.mark_uncertain(i, tick=105)
        self.assertEqual(self.prepare(tick=106)["status"],
                         "CANCELLED_WITHOUT_SEND")

    def test_no_remote_observation_before_uncertain(self):
        self.observe()
        i = self.prepare()["intent_id"]
        with self.assertRaisesRegex(Rejected, "out of sequence"):
            self.outbox.record_untrusted_remote_observation(
                i, tick=104, remote_sample=self.sample(i))

    def test_untrusted_observation_remains_hold(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        r = self.outbox.record_untrusted_remote_observation(
            i, tick=105, remote_sample=self.sample(i))
        self.assertEqual(r["status"], "RECONCILIATION_HOLD")
        self.assertEqual(r["independent_provenance"], "NOT_ATTESTED")
        self.assertFalse(r["check_written"])
        self.assertFalse(r["real_github_api_called"])

    def test_wrong_sha_remote_observation_denied(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        sample = self.sample(i)
        sample["head_sha"] = "b" * 40
        with self.assertRaisesRegex(Rejected, "different intent/head"):
            self.outbox.record_untrusted_remote_observation(
                i, tick=105, remote_sample=sample)

    def test_wrong_external_id_denied(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        sample = self.sample(i)
        sample["external_id"] = "forged"
        with self.assertRaisesRegex(Rejected, "different intent/head"):
            self.outbox.record_untrusted_remote_observation(
                i, tick=105, remote_sample=sample)

    def test_success_claim_from_untrusted_json_denied(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        sample = self.sample(i)
        sample["conclusion"] = "success"
        with self.assertRaisesRegex(Rejected, "not admissible"):
            self.outbox.record_untrusted_remote_observation(
                i, tick=105, remote_sample=sample)

    def test_untrusted_app_id_boolean_denied(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        sample = self.sample(i)
        sample["app_id"] = True
        with self.assertRaisesRegex(Rejected, "not admissible"):
            self.outbox.record_untrusted_remote_observation(
                i, tick=105, remote_sample=sample)

    def test_observation_only_once(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        self.outbox.record_untrusted_remote_observation(
            i, tick=105, remote_sample=self.sample(i))
        with self.assertRaisesRegex(Rejected, "out of sequence"):
            self.outbox.record_untrusted_remote_observation(
                i, tick=106, remote_sample=self.sample(i))

    def test_concurrent_prepare_one_intent(self):
        self.observe()
        def worker(_):
            return OfflineOutbox(Lifecycle(self.db)).prepare(
                GUID, asserted_head_sha=HEAD, tick=104)["intent_id"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(worker, range(2)))
        self.assertEqual(results[0], results[1])
        with self.life._tx() as c:
            count = c.execute("SELECT COUNT(*) FROM outbox_intents").fetchone()[0]
        self.assertEqual(count, 1)

    def test_audit_transition_count(self):
        self.observe()
        i = self.prepare()["intent_id"]
        self.outbox.mark_uncertain(i, tick=104)
        self.outbox.record_untrusted_remote_observation(
            i, tick=105, remote_sample=self.sample(i))
        with self.life._tx() as c:
            types = [r[0] for r in c.execute(
                "SELECT transition FROM outbox_events ORDER BY id")]
        self.assertEqual(types, [
            "PREPARED_LOCAL_ONLY", "UNKNOWN_REMOTE_RESULT",
            "RECONCILIATION_HOLD"
        ])


if __name__ == "__main__":
    unittest.main()
