"""Synthetic tests only. Inputs are not live security evidence."""
import copy
import unittest
from trusted_check_policy import (
    EXPECTED_REPOSITORY, Rejected, evaluate_candidate,
    signed_fixture, verify_webhook,
)

SECRET = b"test-only-webhook-secret-not-real-123"
HEAD = "a" * 40
BASE = "b" * 40


def sample():
    event = {
        "repository": {"full_name": EXPECTED_REPOSITORY},
        "number": 42,
        "pull_request": {
            "head": {"sha": HEAD},
            "base": {"sha": BASE, "ref": "main",
                     "repo": {"full_name": EXPECTED_REPOSITORY}},
            "draft": False,
            "user": {"login": "author"},
        },
    }
    live = {
        "repository": EXPECTED_REPOSITORY, "number": 42,
        "head_sha": HEAD, "base_sha": BASE, "base_ref": "main",
        "author": "author", "draft": False,
        "files": [".github/workflows/env004-audit-provenance.yml"],
        "changed_files": 1,
        "reviews": [{"login": "reviewer", "state": "APPROVED",
                     "commit_id": HEAD, "permission": "write"}],
        "independent_operator_attestation_verified": False,
    }
    return event, live


class WebhookVerificationTests(unittest.TestCase):
    def test_valid_signature(self):
        event, _ = sample()
        body, sig = signed_fixture(event, SECRET)
        self.assertEqual(verify_webhook(body, sig, SECRET), event)

    def test_bad_signature(self):
        event, _ = sample()
        body, sig = signed_fixture(event, SECRET)
        with self.assertRaises(Rejected):
            verify_webhook(body + b" ", sig, SECRET)

    def test_wrong_secret(self):
        event, _ = sample()
        body, sig = signed_fixture(event, SECRET)
        with self.assertRaises(Rejected):
            verify_webhook(body, sig, b"different-test-only-secret-123")

    def test_short_secret(self):
        event, _ = sample()
        body, sig = signed_fixture(event, SECRET)
        with self.assertRaises(Rejected):
            verify_webhook(body, sig, b"short")

    def test_invalid_signature_format(self):
        with self.assertRaises(Rejected):
            verify_webhook(b"{}", "sha1=" + "0" * 40, SECRET)

    def test_invalid_json(self):
        import hashlib
        import hmac
        body = b"garbage"
        sig = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        with self.assertRaises(Rejected):
            verify_webhook(body, sig, SECRET)


class CandidateDecisionTests(unittest.TestCase):
    def setUp(self):
        self.event, self.live = sample()

    def assertBlock(self, reason):
        got = evaluate_candidate(self.event, self.live)
        self.assertEqual(got.status, "BLOCK")
        self.assertIn(reason, got.reasons)
        self.assertFalse(got.as_dict()["check_written"])

    def test_no_attestation_blocks_even_with_approver(self):
        self.assertBlock("OPERATOR_INDEPENDENCE_NOT_ATTESTED")

    def test_matching_fixture_still_only_candidate(self):
        self.live["independent_operator_attestation_verified"] = True
        decision = evaluate_candidate(self.event, self.live)
        self.assertEqual(decision.status, "CANDIDATE_ONLY_NOT_ENFORCED")
        self.assertFalse(decision.as_dict()["check_written"])
        self.assertEqual(decision.as_dict()["enforcement"], "NOT_DEPLOYED")

    def test_old_head_event(self):
        self.live["head_sha"] = "c" * 40
        self.assertBlock("STALE_EVENT_OR_PR")

    def test_old_base_event(self):
        self.live["base_sha"] = "c" * 40
        self.assertBlock("STALE_EVENT_OR_PR")

    def test_no_review(self):
        self.live["reviews"] = []
        self.assertBlock("NO_ELIGIBLE_CURRENT_HEAD_REVIEW")

    def test_author_self_approval(self):
        self.live["reviews"][0]["login"] = "author"
        self.assertBlock("NO_ELIGIBLE_CURRENT_HEAD_REVIEW")

    def test_stale_review(self):
        self.live["reviews"][0]["commit_id"] = "c" * 40
        self.assertBlock("NO_ELIGIBLE_CURRENT_HEAD_REVIEW")

    def test_read_only_reviewer(self):
        self.live["reviews"][0]["permission"] = "read"
        self.assertBlock("NO_ELIGIBLE_CURRENT_HEAD_REVIEW")

    def test_file_count_mismatch(self):
        self.live["changed_files"] = 3
        self.assertBlock("FILE_COUNT_MISMATCH")

    def test_duplicate_files(self):
        self.live["files"].append(self.live["files"][0])
        self.live["changed_files"] = 2
        self.assertBlock("INVALID_FILE_SET")

    def test_bad_repo(self):
        self.event["repository"]["full_name"] = "another/repo"
        self.assertBlock("WRONG_REPOSITORY")

    def test_wrong_base(self):
        self.event["pull_request"]["base"]["ref"] = "other"
        self.assertBlock("WRONG_BASE_REF")

    def test_draft(self):
        self.event["pull_request"]["draft"] = True
        self.assertBlock("DRAFT_PR")

    def test_missing_evidence(self):
        del self.live["head_sha"]
        self.assertBlock("INCOMPLETE_OR_MALFORMED_EVIDENCE")

    def test_invalid_sha(self):
        self.live["base_sha"] = "not-a-sha"
        self.assertBlock("INVALID_SHA")

    def test_attested_flag_cannot_grant_without_review(self):
        self.live["independent_operator_attestation_verified"] = True
        self.live["reviews"] = []
        self.assertBlock("NO_ELIGIBLE_CURRENT_HEAD_REVIEW")


if __name__ == "__main__":
    unittest.main()
