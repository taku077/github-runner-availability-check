"""SEC151 offline cross-snapshot race tests: 0 network, 0 credentials."""
import copy
import unittest
from datetime import datetime, timedelta, timezone

from prepost_consistency import compare_prepost_window
from test_installation_scope import fixture as installation_fixture, NOW
from test_provider_readback import fixture as provider_fixture, APP, HEAD
from test_check_page_chain import make_pages
from trusted_check_policy import Rejected

MAIN = "c" * 40


def fixture():
    ins = installation_fixture()
    p = provider_fixture()
    pr = copy.deepcopy(p["live_pr_before"])
    pr["head"]["repo"] = {
        "id": 1450293513,
        "full_name": "taku077/github-runner-availability-check"}
    pr["base"]["sha"] = MAIN
    pr["base"]["repo"]["id"] = 1450293513
    pr["merged"] = False
    return {
        "pre_receipts": copy.deepcopy(ins["receipts"]),
        "post_receipts": copy.deepcopy(ins["receipts"]),
        "pr_before": copy.deepcopy(pr),
        "pr_after": copy.deepcopy(pr),
        "page_responses": make_pages(1),
        "check_run_by_id": copy.deepcopy(p["check_run_by_id"]),
        "local_intent": copy.deepcopy(p["local_intent"]),
        "expected_pr_number": 4,
        "pinned_main_sha": MAIN,
        "pinned_app_id": APP,
        "pinned_installation_id": ins["independently_pinned_installation_id"],
        "started_at_utc": NOW,
        "finished_at_utc": NOW + timedelta(seconds=30),
    }


class PrePostConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def deny(self, match):
        with self.assertRaisesRegex(Rejected, match):
            compare_prepost_window(**self.f)

    def before(self, key):
        return self.f["pre_receipts"][key]["body"]

    def after(self, key):
        return self.f["post_receipts"][key]["body"]

    def test_synthetic_consistent_window_never_authorizes(self):
        r = compare_prepost_window(**self.f).as_dict()
        self.assertEqual(r["status"],
                         "SYNTHETIC_PREPOST_MATCH_NOT_AUTHORIZED")
        for name in ("provider_transport_authenticated",
                     "app_credentials_authenticated",
                     "operator_authorized",
                     "freshness_independently_attested",
                     "ruleset_enforcement_verified",
                     "check_written", "merge_authorized"):
            self.assertFalse(r[name], name)
        self.assertEqual(r["head_sha"], HEAD)

    def test_one_second_window_is_only_candidate(self):
        self.f["finished_at_utc"] = NOW + timedelta(seconds=1)
        self.assertFalse(compare_prepost_window(**self.f).as_dict()[
            "merge_authorized"])

    def test_exact_120_seconds_is_only_candidate(self):
        self.f["finished_at_utc"] = NOW + timedelta(seconds=120)
        self.assertFalse(compare_prepost_window(**self.f).as_dict()[
            "merge_authorized"])

    def test_zero_duration_rejected(self):
        self.f["finished_at_utc"] = NOW
        self.deny("observation window reversed")

    def test_reversed_clock_rejected(self):
        self.f["finished_at_utc"] = NOW - timedelta(seconds=1)
        self.deny("observation window reversed")

    def test_over_two_minutes_rejected(self):
        self.f["finished_at_utc"] = NOW + timedelta(seconds=121)
        self.deny("observation window reversed")

    def test_local_time_after_rejected(self):
        self.f["finished_at_utc"] = self.f["finished_at_utc"].astimezone(
            timezone(timedelta(hours=9)))
        self.deny("non-UTC observation clock")

    def test_naive_start_time_rejected(self):
        self.f["started_at_utc"] = NOW.replace(tzinfo=None)
        self.deny("non-UTC observation clock")

    def test_missing_finish_clock_rejected(self):
        self.f["finished_at_utc"] = None
        self.deny("non-UTC observation clock")

    def test_invalid_pin_sha_rejected(self):
        self.f["pinned_main_sha"] = "bad"
        self.deny("invalid pinned PR/base identity")

    def test_bool_pr_number_rejected(self):
        self.f["expected_pr_number"] = True
        self.deny("invalid pinned PR/base identity")

    def test_wrong_pinned_app_rejected(self):
        self.f["pinned_app_id"] = 15368
        self.deny("invalid or GitHub Actions")

    def test_app_id_mutation_after_rejected(self):
        self.after("app")["id"] = 999
        self.deny("GitHub App identity mismatch")

    def test_app_slug_changed_but_both_valid_rejected(self):
        self.after("app")["slug"] = "new-valid-slug"
        self.deny("App installation or token scope drift")

    def test_app_permissions_escalation_rejected(self):
        self.after("app")["permissions"]["contents"] = "write"
        self.deny("App permissions")

    def test_installation_suspended_after_rejected(self):
        self.after("installation")["suspended_at"] = "2026-11-23T00:00:10Z"
        self.deny("installation identity")

    def test_installation_suspended_before_rejected(self):
        self.before("installation")["suspended_at"] = "2026-11-23T00:00:00Z"
        self.deny("installation identity")

    def test_installation_permissions_escalation_rejected(self):
        self.after("installation")["permissions"]["checks"] = "admin"
        self.deny("installation permissions")

    def test_installation_repo_scope_changed_rejected(self):
        self.after("installation")["repository_selection"] = "all"
        self.deny("installation identity")

    def test_repo_id_changed_rejected(self):
        self.after("repositories")["repositories"][0]["id"] = 999
        self.deny("unexpected repository identity")

    def test_repo_count_changed_rejected(self):
        self.after("repositories")["total_count"] = 2
        self.deny("repository enumeration")

    def test_token_permissions_changed_rejected(self):
        self.after("scoped_token_metadata")["permissions"]["contents"] = "read"
        self.deny("scoped token permissions")

    def test_token_expiration_changed_but_valid_rejected(self):
        self.after("scoped_token_metadata")["expires_at"] = (
            "2026-11-23T00:35:00Z")
        self.deny("App installation or token scope drift")

    def test_token_expires_within_two_minutes_after_rejected(self):
        self.f["started_at_utc"] = NOW + timedelta(minutes=28)
        self.f["finished_at_utc"] = NOW + timedelta(minutes=28, seconds=30)
        self.deny("expired or outside safe lifetime")

    def test_metadata_changed_despite_same_identity_rejected(self):
        self.after("installation")["updated_at"] = "2026-11-23T00:00:01Z"
        self.deny("App installation or token scope drift")

    def test_unserializable_response_rejected(self):
        self.after("app")["other"] = {1, 2}
        self.deny("unserializable snapshot data")

    def test_secrets_in_after_snapshot_rejected(self):
        self.after("scoped_token_metadata")["token"] = "SYNTHETIC_ONLY"
        self.deny("secret or token material")

    def test_bad_http_status_after_rejected(self):
        self.f["post_receipts"]["installation"]["status_code"] = 403
        self.deny("endpoint, status or credential kind mismatch")

    def test_wrong_auth_kind_after_rejected(self):
        self.f["post_receipts"]["repositories"]["credential_kind"] = "app_jwt"
        self.deny("endpoint, status or credential kind mismatch")

    def test_missing_after_receipt_rejected(self):
        del self.f["post_receipts"]["installation"]
        self.deny("incomplete or excessive provider receipts")

    def test_changed_head_during_readback_rejected(self):
        self.f["pr_after"]["head"]["sha"] = "d" * 40
        self.deny("PR head, base, repository or state mismatch")

    def test_both_wrong_head_rejected(self):
        for name in ("pr_before", "pr_after"):
            self.f[name]["head"]["sha"] = "d" * 40
        self.deny("PR head, base, repository or state mismatch")

    def test_base_sha_changed_during_readback_rejected(self):
        self.f["pr_after"]["base"]["sha"] = "e" * 40
        self.deny("PR head, base, repository or state mismatch")

    def test_base_sha_wrong_both_rejected(self):
        for name in ("pr_before", "pr_after"):
            self.f[name]["base"]["sha"] = "e" * 40
        self.deny("PR head, base, repository or state mismatch")

    def test_head_repo_id_changed_rejected(self):
        self.f["pr_after"]["head"]["repo"]["id"] = 2
        self.deny("PR head, base, repository or state mismatch")

    def test_base_repo_id_changed_rejected(self):
        self.f["pr_before"]["base"]["repo"]["id"] = 3
        self.deny("PR head, base, repository or state mismatch")

    def test_wrong_head_repo_name_rejected(self):
        self.f["pr_before"]["head"]["repo"]["full_name"] = "other/repo"
        self.deny("PR head, base, repository or state mismatch")

    def test_pr_number_changed_rejected(self):
        self.f["pr_after"]["number"] = 5
        self.deny("PR head, base, repository or state mismatch")

    def test_closed_pr_after_rejected(self):
        self.f["pr_after"]["state"] = "closed"
        self.deny("PR head, base, repository or state mismatch")

    def test_draft_pr_after_rejected(self):
        self.f["pr_after"]["draft"] = True
        self.deny("PR head, base, repository or state mismatch")

    def test_merged_pr_after_rejected(self):
        self.f["pr_after"]["merged"] = True
        self.deny("PR head, base, repository or state mismatch")

    def test_missing_pr_metadata_rejected(self):
        del self.f["pr_before"]["base"]["sha"]
        self.deny("incomplete PR identity snapshot")

    def test_local_intent_stale_rejected(self):
        self.f["local_intent"]["head_sha"] = "b" * 40
        self.deny("PR head, base, repository or state mismatch")

    def test_missing_local_intent_rejected(self):
        self.f["local_intent"] = None
        self.deny("missing durable local intent")

    def test_run_app_id_not_installation_rejected(self):
        self.f["check_run_by_id"]["app"]["id"] = 15368
        self.deny("check run head/source/intent/conclusion mismatch")

    def test_run_head_wrong_rejected(self):
        self.f["check_run_by_id"]["head_sha"] = "e" * 40
        self.deny("check run head/source/intent/conclusion mismatch")

    def test_missing_check_page_rejected(self):
        self.f["page_responses"] = []
        self.deny("missing or excessive API pages")

    def test_check_page_filtered_latest_rejected(self):
        self.f["page_responses"][0]["request_url"] = (
            self.f["page_responses"][0]["request_url"].replace(
                "filter=all", "filter=latest"))
        self.deny("API filtering or page size differs")

    def test_forged_positive_policy_flag_does_not_override(self):
        self.after("installation")["operator_approved"] = True
        self.deny("App installation or token scope drift")


if __name__ == "__main__":
    unittest.main()
