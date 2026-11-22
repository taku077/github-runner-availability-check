"""SEC155 paired readback drift negatives; no external API access or keys."""
import copy
import unittest
from datetime import datetime, timedelta, timezone

from ruleset_drift import audit_paired_readbacks
from test_ruleset_preflight import live_shape, fantasy_green, APP, HEAD
from trusted_check_policy import Rejected

NOW = datetime(2026, 11, 22, 19, 0, tzinfo=timezone.utc)
MAIN = "b" * 40


def _snapshot(kind="observed"):
    f = fantasy_green() if kind == "hypothetical" else live_shape()
    return {
        "repository": copy.deepcopy(f["repository"]),
        "ruleset": copy.deepcopy(f["ruleset"]),
        "pull_request": copy.deepcopy(f["pull_request"]),
        "reviews": copy.deepcopy(f["reviews"]),
        "check_run_list": copy.deepcopy(f["check_run_list"]),
        "main_head_sha": MAIN,
    }


def fixture(kind="observed"):
    s = _snapshot(kind)
    return {
        "before": copy.deepcopy(s),
        "after": copy.deepcopy(s),
        "independently_pinned_app_id": APP if kind == "hypothetical" else None,
        "expected_main_head_sha": MAIN,
        "started_at_utc": NOW,
        "finished_at_utc": NOW + timedelta(seconds=30),
    }


def set_value(root, *path, value):
    d = root
    for key in path[:-1]:
        d = d[key]
    d[path[-1]] = value


class PairedReadbackTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def check(self, *expected):
        result = audit_paired_readbacks(**self.f).as_dict()
        self.assertEqual(result["status"],
                         "READONLY_DRIFT_PREFLIGHT_NOT_AUTHORIZED")
        for reason in expected:
            self.assertIn(reason, result["findings"])
        for name in ("digest_is_external_signature",
                     "provider_authenticated",
                     "independent_operator_attested",
                     "independent_enforcement_verified",
                     "check_written", "merge_authorized",
                     "production_deployed"):
            self.assertFalse(result[name], name)
        return result

    def deny(self):
        with self.assertRaises(Rejected):
            audit_paired_readbacks(**self.f)

    def test_actual_public_shape_still_not_authorized(self):
        self.check("GATE_INDEPENDENT_CHECK_NOT_REQUIRED",
                   "GATE_REVIEW_APPROVAL_MINIMUM_MISSING",
                   "EXTERNAL_POLICY_AND_OPERATOR_NOT_ATTESTED")

    def test_identical_forged_green_snapshots_never_prove_origin(self):
        self.f = fixture("hypothetical")
        self.check("EXTERNAL_POLICY_AND_OPERATOR_NOT_ATTESTED",
                   "AUTHENTICATED_PROVIDER_COLLECTION_NOT_IMPLEMENTED",
                   "REAL_RULESET_REJECTION_AND_RECOVERY_NOT_TESTED")

    def test_stable_fingerprint_of_same_untrusted_data(self):
        a = self.check()
        b = audit_paired_readbacks(**copy.deepcopy(self.f)).as_dict()
        self.assertEqual(a["comparison_digest_sha256"],
                         b["comparison_digest_sha256"])
        self.assertEqual(len(a["comparison_digest_sha256"]), 64)

    def test_change_digest_does_not_make_signature(self):
        a = self.check()
        self.f["after"]["ruleset"]["name"] = "new name"
        b = self.check("RULESET_CHANGED_DURING_COLLECTION")
        self.assertNotEqual(a["comparison_digest_sha256"],
                            b["comparison_digest_sha256"])
        self.assertFalse(b["digest_is_external_signature"])

    def test_strict_120_second_interval_only_synthetic(self):
        self.f["finished_at_utc"] = NOW + timedelta(seconds=120)
        self.check("EXTERNAL_POLICY_AND_OPERATOR_NOT_ATTESTED")

    def test_positive_snapshot_never_grants_merge_even_with_review(self):
        self.f = fixture("hypothetical")
        self.check("REAL_RULESET_REJECTION_AND_RECOVERY_NOT_TESTED")

    def test_ruleset_enforcement_changed(self):
        self.f["after"]["ruleset"]["enforcement"] = "disabled"
        self.check("RULESET_CHANGED_DURING_COLLECTION",
                   "GATE_RULESET_NOT_ACTIVE")

    def test_ruleset_status_source_changed(self):
        checks = self.f["after"]["ruleset"]["rules"][3][
            "parameters"]["required_status_checks"]
        checks[0]["integration_id"] = APP
        self.check("RULESET_CHANGED_DURING_COLLECTION")

    def test_ruleset_bypass_actor_added(self):
        self.f["after"]["ruleset"]["bypass_actors"] = [
            {"actor_id": 1, "actor_type": "User", "bypass_mode": "always"}]
        self.check("RULESET_CHANGED_DURING_COLLECTION",
                   "GATE_RULESET_BYPASS_NOT_EXCLUDED")

    def test_ruleset_required_review_changed(self):
        self.f["after"]["ruleset"]["rules"][2]["parameters"][
            "required_approving_review_count"] = 1
        self.check("RULESET_CHANGED_DURING_COLLECTION")

    def test_ruleset_scope_changed(self):
        self.f["after"]["ruleset"]["conditions"]["ref_name"][
            "exclude"] = ["main"]
        self.check("RULESET_CHANGED_DURING_COLLECTION",
                   "GATE_DEFAULT_BRANCH_SCOPE_UNVERIFIED")

    def test_ruleset_metadata_updated(self):
        self.f["after"]["ruleset"]["updated_at"] = (
            "2026-11-23T03:59:00Z")
        self.check("RULESET_CHANGED_DURING_COLLECTION")

    def test_repository_identity_changed(self):
        self.f["after"]["repository"]["id"] = 12
        self.check("REPOSITORY_IDENTITY_DRIFT",
                   "GATE_TARGET_REPOSITORY_NOT_VERIFIED")

    def test_repository_owner_changed(self):
        self.f["after"]["repository"]["owner"]["type"] = "Organization"
        self.check("REPOSITORY_IDENTITY_DRIFT")

    def test_pr_head_changed(self):
        self.f["after"]["pull_request"]["head"]["sha"] = "c" * 40
        self.check("PULL_REQUEST_CHANGED_DURING_COLLECTION")

    def test_pr_base_changed(self):
        self.f["after"]["pull_request"]["base"]["sha"] = "c" * 40
        self.check("PULL_REQUEST_CHANGED_DURING_COLLECTION")

    def test_pr_draft_status_changed(self):
        self.f["after"]["pull_request"]["draft"] = False
        self.check("PULL_REQUEST_CHANGED_DURING_COLLECTION")

    def test_pr_review_collection_changed(self):
        self.f["after"]["reviews"] = [{
            "id": 1, "state": "APPROVED",
            "user": {"id": 4321}, "commit_id": HEAD}]
        self.check("REVIEWS_CHANGED_DURING_COLLECTION")

    def test_check_run_changed_from_running_to_success(self):
        self.f["after"]["check_run_list"]["check_runs"][0][
            "conclusion"] = "success-2"
        self.check("CHECK_RUNS_CHANGED_DURING_COLLECTION")

    def test_check_source_changed(self):
        self.f["after"]["check_run_list"]["check_runs"][0][
            "app"]["id"] = APP
        self.check("CHECK_RUNS_CHANGED_DURING_COLLECTION")

    def test_base_commit_changed_during_collection(self):
        self.f["after"]["main_head_sha"] = "f" * 40
        self.check("BASE_SHA_CHANGED_OR_PIN_MISMATCH")

    def test_independently_pinned_base_mismatch(self):
        self.f["expected_main_head_sha"] = "f" * 40
        self.check("BASE_SHA_CHANGED_OR_PIN_MISMATCH")

    def test_clock_zero_duration_rejected(self):
        self.f["finished_at_utc"] = NOW
        self.deny()

    def test_clock_reversed_rejected(self):
        self.f["finished_at_utc"] = NOW - timedelta(seconds=1)
        self.deny()

    def test_clock_121_second_rejected(self):
        self.f["finished_at_utc"] = NOW + timedelta(seconds=121)
        self.deny()

    def test_clock_not_utc_rejected(self):
        self.f["finished_at_utc"] = NOW.astimezone(
            timezone(timedelta(hours=9)))
        self.deny()

    def test_clock_naive_rejected(self):
        self.f["started_at_utc"] = NOW.replace(tzinfo=None)
        self.deny()

    def test_broken_pinned_sha_rejected(self):
        self.f["expected_main_head_sha"] = "bad"
        self.deny()

    def test_broken_snapshot_main_sha_rejected(self):
        self.f["before"]["main_head_sha"] = "bad"
        self.deny()

    def test_snapshot_must_include_every_field(self):
        del self.f["before"]["check_run_list"]
        self.deny()

    def test_no_extra_root_fields(self):
        self.f["after"]["untrusted_extra"] = True
        self.deny()

    def test_boolean_head_list_rejected(self):
        self.f["after"]["main_head_sha"] = True
        self.deny()

    def test_review_body_not_a_list_rejected(self):
        self.f["before"]["reviews"] = {}
        self.deny()

    def test_check_body_not_a_dict_rejected(self):
        self.f["after"]["check_run_list"] = []
        self.deny()

    def test_ruleset_body_not_a_dict_rejected(self):
        self.f["after"]["ruleset"] = None
        self.deny()

    def test_nonfinite_numeric_payload_rejected(self):
        self.f["after"]["repository"]["nan"] = float("nan")
        self.deny()

    def test_non_json_set_payload_rejected(self):
        self.f["before"]["repository"]["set"] = {1, 2}
        self.deny()

    def test_large_payload_rejected(self):
        self.f["after"]["ruleset"]["filler"] = "A" * 200000
        self.deny()

    def test_matching_snapshots_with_fake_operator_flag_not_attested(self):
        self.f = fixture("hypothetical")
        for name in ("before", "after"):
            self.f[name]["pull_request"]["independent_operator_verified"] = True
        self.check("EXTERNAL_POLICY_AND_OPERATOR_NOT_ATTESTED")

    def test_missing_app_pin_rejected_as_gate_blocker(self):
        self.f = fixture("hypothetical")
        self.f["independently_pinned_app_id"] = None
        self.check("GATE_INDEPENDENT_APP_NOT_PINNED")


if __name__ == "__main__":
    unittest.main()
