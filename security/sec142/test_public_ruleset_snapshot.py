"""SEC155: reproducible offline audit of a historical public API readback.

A connector captured these selected fields on 2026-11-23 JST. This immutable
fixture is PR-controlled, unsigned, and is NOT a current provider guarantee.
No external API, secrets or remote App credentials are used in these tests.
"""
import copy
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ruleset_preflight import audit_readonly_gate
from ruleset_drift import audit_paired_readbacks

FILE = (Path(__file__).resolve().parent / "fixtures" /
        "sec155_public_ruleset_readback_20261123.json")


def loaded():
    return json.loads(FILE.read_text(encoding="utf-8"))


class RecordedPublicReadbackTests(unittest.TestCase):
    def setUp(self):
        self.record = loaded()
        self.body = self.record["evidence"]

    def test_historical_public_check_is_not_independent(self):
        self.assertEqual(self.body["check_run_list"]["total_count"], 1)
        runs = self.body["check_run_list"]["check_runs"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["app"]["id"], 15368)
        self.assertNotEqual(runs[0]["name"],
                            "pcfm-independent-admission")

    def test_zero_submitted_reviews_in_historical_snapshot(self):
        self.assertEqual(self.body["reviews"], [])
        self.assertTrue(self.body["pull_request"]["draft"])
        self.assertFalse(self.body["pull_request"]["merged"])

    def test_live_shape_source_only_preflight_still_blocked(self):
        result = audit_readonly_gate(
            repository=self.body["repository"],
            ruleset=self.body["ruleset"],
            pull_request=self.body["pull_request"],
            reviews=self.body["reviews"],
            check_run_list=self.body["check_run_list"],
            independently_pinned_app_id=None).as_dict()
        self.assertEqual(result["status"], "READONLY_PREFLIGHT_NOT_ACCEPTED")
        for reason in ("REVIEW_APPROVAL_MINIMUM_MISSING",
                       "INDEPENDENT_APP_NOT_PINNED",
                       "INDEPENDENT_CHECK_NOT_REQUIRED",
                       "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT",
                       "CURRENT_SHA_APPROVALS_NOT_OBSERVED",
                       "INDEPENDENT_CHECK_RUN_NOT_OBSERVED",
                       "EXTERNAL_OPERATOR_AND_PROVIDER_AUTHENTICATION_NOT_PROVEN",
                       "LIVE_REJECTION_TEST_NOT_PROVEN"):
            self.assertIn(reason, result["findings"])
        self.assertFalse(result["merge_authorized"])

    def test_historical_snapshot_parses_as_same_untrusted_pair(self):
        start = datetime(2026, 11, 22, 19, 0, tzinfo=timezone.utc)
        r = audit_paired_readbacks(
            before=copy.deepcopy(self.body), after=copy.deepcopy(self.body),
            independently_pinned_app_id=None,
            expected_main_head_sha=self.body["main_head_sha"],
            started_at_utc=start,
            finished_at_utc=start + timedelta(seconds=30)).as_dict()
        self.assertEqual(
            r["status"], "READONLY_DRIFT_PREFLIGHT_NOT_AUTHORIZED")
        self.assertFalse(r["provider_authenticated"])
        self.assertFalse(r["merge_authorized"])

    def test_historical_rule_change_detected_in_replay(self):
        start = datetime(2026, 11, 22, 19, 0, tzinfo=timezone.utc)
        modified = copy.deepcopy(self.body)
        modified["ruleset"]["rules"][1]["parameters"][
            "required_approving_review_count"] = 1
        r = audit_paired_readbacks(
            before=self.body, after=modified,
            independently_pinned_app_id=None,
            expected_main_head_sha=self.body["main_head_sha"],
            started_at_utc=start,
            finished_at_utc=start + timedelta(seconds=30)).as_dict()
        self.assertIn("RULESET_CHANGED_DURING_COLLECTION", r["findings"])
        self.assertFalse(r["independent_enforcement_verified"])

    def test_historical_source_uris_bound_to_recorded_commit(self):
        self.assertEqual(self.record["observed_date_jst"], "2026-11-23")
        self.assertIn(self.record["observed_pr_head_sha"],
                      self.record["source_urls"]["check_runs"])
        self.assertEqual(self.record["observed_base_sha"],
                         self.body["main_head_sha"])
        self.assertEqual(self.record["observed_pr_head_sha"],
                         self.body["pull_request"]["head"]["sha"])

    def test_original_ruleset_required_check_source_is_actions(self):
        self.assertEqual(self.body["ruleset"]["id"], 27806733)
        rules = self.body["ruleset"]["rules"]
        check = next(x for x in rules
                     if x["type"] == "required_status_checks")
        self.assertEqual(check["parameters"]["required_status_checks"], [
            {"context": "env003-main-rules", "integration_id": 15368}
        ])
        required = next(x for x in rules if x["type"] == "pull_request")
        self.assertEqual(
            required["parameters"]["required_approving_review_count"], 0)

    def test_fixture_contains_no_raw_sensitive_auth_fields(self):
        source = FILE.read_text(encoding="utf-8").lower()
        for token in ('"authorization"', '"private_key"', '"access_token"',
                      '"client_secret"', '"password"', '"jwt"', '"token"'):
            self.assertNotIn(token, source)

    def test_replayed_hash_is_not_independent_signed_provenance(self):
        self.assertFalse(self.record["independent_enforcement_accepted"])
        self.assertFalse(self.record["production_deployed"])
        self.assertIn("not independently authenticated",
                      self.record["notice"].lower())


if __name__ == "__main__":
    unittest.main()
