"""SEC143 synthetic tests. No real GitHub data or credentials."""
import concurrent.futures
import copy
import tempfile
import unittest
from pathlib import Path
from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, signed_fixture
from webhook_intake import DeliveryLedger, receive_delivery

SECRET = b"synthetic-only-not-a-real-github-secret-123"
D1 = "0b989ba4-242f-11e5-81e1-c7b6966d2516"
D2 = "0b989ba4-242f-11e5-81e1-c7b6966d2517"


def event():
    return {
        "repository": {"full_name": EXPECTED_REPOSITORY},
        "installation": {"id": 123}, "number": 4,
        "pull_request": {"head": {"sha": "a" * 40}}
    }


class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sec143-")
        self.path = Path(self.temp.name) / "receipts.sqlite3"
        self.store = DeliveryLedger(self.path)
        self.payload = event()

    def tearDown(self):
        self.temp.cleanup()

    def receive(self, payload=None, delivery_id=D1, event_name="pull_request",
                signature=None, secret=SECRET, store=None):
        raw, good_sig = signed_fixture(self.payload if payload is None else payload, SECRET)
        return receive_delivery(
            body=raw, signature=good_sig if signature is None else signature,
            secret=secret, delivery_id=delivery_id, event_name=event_name,
            ledger=self.store if store is None else store)

    def deny(self, needle, **kwargs):
        with self.assertRaisesRegex(Rejected, needle):
            self.receive(**kwargs)

    def test_signed_delivery_only_observed(self):
        r = self.receive().as_dict()
        self.assertFalse(r["check_written"])
        self.assertEqual(r["enforcement"], "NOT_DEPLOYED")
        self.assertFalse(r["independent_reviewer_verified"])

    def test_replay_same_id_denied(self):
        self.receive()
        self.deny("duplicate delivery", delivery_id=D1)

    def test_replay_across_restarts_denied(self):
        self.receive()
        self.deny("duplicate delivery", store=DeliveryLedger(self.path))

    def test_same_id_changed_payload_still_denied(self):
        self.receive()
        p = copy.deepcopy(self.payload)
        p["pull_request"]["head"]["sha"] = "c" * 40
        self.deny("duplicate delivery", payload=p)

    def test_bad_hmac_does_not_poison_ledger(self):
        self.deny("invalid signature", signature="sha256=" + "0" * 64)
        self.receive()

    def test_unexpected_event_does_not_poison_ledger(self):
        self.deny("unexpected webhook event", event_name="push")
        self.receive()

    def test_wrong_repo_does_not_poison_ledger(self):
        p = copy.deepcopy(self.payload)
        p["repository"]["full_name"] = "different/repo"
        self.deny("unexpected signed event scope", payload=p)
        self.receive()

    def test_missing_installation_does_not_poison_ledger(self):
        p = copy.deepcopy(self.payload)
        del p["installation"]
        self.deny("incomplete signed event", payload=p)
        self.receive()

    def test_bool_installation_is_invalid(self):
        p = copy.deepcopy(self.payload)
        p["installation"]["id"] = True
        self.deny("unexpected signed event scope", payload=p)

    def test_bool_pr_number_is_invalid(self):
        p = copy.deepcopy(self.payload)
        p["number"] = True
        self.deny("unexpected signed event scope", payload=p)

    def test_invalid_head_sha_is_denied(self):
        p = copy.deepcopy(self.payload)
        p["pull_request"]["head"]["sha"] = "short"
        self.deny("unexpected signed event scope", payload=p)

    def test_malformed_delivery_id_is_denied(self):
        self.deny("invalid X-GitHub-Delivery", delivery_id="../../foo")
        self.receive()

    def test_new_delivery_id_may_repeat_content(self):
        self.receive()
        self.receive(delivery_id=D2)

    def test_review_event_does_not_grant_review(self):
        r = self.receive(event_name="pull_request_review").as_dict()
        self.assertEqual(r["status"], "WEBHOOK_OBSERVED_ONLY_NOT_AUTHORIZED")
        self.assertFalse(r["independent_reviewer_verified"])

    def test_same_id_concurrent_connections_only_one_succeeds(self):
        def worker(_):
            try:
                self.receive(store=DeliveryLedger(self.path))
                return "observed"
            except Rejected:
                return "rejected"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
            results = list(e.map(worker, [0, 1]))
        self.assertCountEqual(results, ["observed", "rejected"])

    def test_nonexistent_parent_fails_closed(self):
        with self.assertRaises(Rejected):
            DeliveryLedger(self.path.parent / "missing" / "ledger.sqlite3")

    def test_wrong_secret_rejected_without_claim(self):
        self.deny("invalid signature", secret=b"wrong-secret-for-only-synthetic-tests")
        self.receive()


if __name__ == "__main__":
    unittest.main()
