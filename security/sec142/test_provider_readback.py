"""SEC147 synthetic GitHub Check Run API-shape verification tests; no network."""
import copy
import unittest
from provider_readback import compare_check_readback
from trusted_check_policy import Rejected

REPO = "taku077/github-runner-availability-check"
HEAD = "a" * 40
INTENT = "b" * 64
APP = 987654  # Fake id; NO GitHub App has been installed by these tests.


def fixture():
    intent = {"intent_id": INTENT, "head_sha": HEAD,
              "status": "UNKNOWN_REMOTE_RESULT",
              "check_written": False}
    pr = {"number": 4, "head": {"sha": HEAD},
          "base": {"ref": "main", "repo": {"full_name": REPO}},
          "state": "open", "draft": False}
    run = {"id": 11223344, "name": "pcfm-independent-admission",
           "head_sha": HEAD, "external_id": INTENT,
           "app": {"id": APP}, "status": "completed",
           "conclusion": "success"}
    return {"local_intent": intent, "live_pr_before": pr,
            "live_pr_after": copy.deepcopy(pr),
            "check_run_by_id": run,
            "check_run_list": {"total_count": 1,
                               "check_runs": [copy.deepcopy(run)]},
            "expected_app_id": APP}


class ProviderReadbackTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def deny(self, expected):
        with self.assertRaisesRegex(Rejected, expected):
            compare_check_readback(**self.data)

    def test_matching_synthetic_readback_never_authorizes(self):
        r = compare_check_readback(**self.data).as_dict()
        self.assertEqual(r["status"],
                         "SYNTHETIC_MATCH_UNTRUSTED_NOT_AUTHORIZED")
        self.assertFalse(r["api_authenticated"])
        self.assertFalse(r["merge_authorized"])
        self.assertFalse(r["check_written"])
        self.assertFalse(r["independent_operator_attested"])
        self.assertFalse(r["ruleset_enforcement_verified"])

    def test_current_github_actions_app_is_not_independent(self):
        self.data["expected_app_id"] = 15368
        self.deny("untrusted or invalid expected App")

    def test_bool_fake_app_id_rejected(self):
        self.data["expected_app_id"] = True
        self.deny("untrusted or invalid expected App")

    def test_wrong_app_source_rejected(self):
        self.data["check_run_by_id"]["app"]["id"] = 15368
        self.deny("check run head/source")

    def test_wrong_check_name_rejected(self):
        self.data["check_run_by_id"]["name"] = "env003-main-rules"
        self.deny("check run head/source")

    def test_wrong_head_sha_rejected(self):
        self.data["check_run_by_id"]["head_sha"] = "c" * 40
        self.deny("check run head/source")

    def test_merge_ref_sha_rejected_instead_of_pr_head(self):
        self.data["check_run_by_id"]["head_sha"] = "d" * 40
        self.deny("check run head/source")

    def test_wrong_external_id_rejected(self):
        self.data["check_run_by_id"]["external_id"] = "other"
        self.deny("check run head/source")

    def test_check_still_running_rejected(self):
        self.data["check_run_by_id"]["status"] = "in_progress"
        self.deny("check run head/source")

    def test_check_conclusion_failure_rejected(self):
        self.data["check_run_by_id"]["conclusion"] = "failure"
        self.deny("check run head/source")

    def test_check_neutral_conclusion_rejected(self):
        self.data["check_run_by_id"]["conclusion"] = "neutral"
        self.deny("check run head/source")

    def test_no_remote_uncertainty_rejected(self):
        self.data["local_intent"]["status"] = "PREPARED_LOCAL_ONLY"
        self.deny("no uncertain remote result")

    def test_cancelled_intent_rejected(self):
        self.data["local_intent"]["status"] = "CANCELLED_WITHOUT_SEND"
        self.deny("no uncertain remote result")

    def test_forged_local_check_written_flag_rejected(self):
        self.data["local_intent"]["check_written"] = True
        self.deny("already claims a check write")

    def test_invalid_local_intent_sha_rejected(self):
        self.data["local_intent"]["head_sha"] = "short"
        self.deny("invalid outbox intent")

    def test_pr_head_mismatch_rejected(self):
        self.data["live_pr_before"]["head"]["sha"] = "c" * 40
        self.deny("PR changed during provider readback")

    def test_pr_updated_after_first_read_rejected(self):
        self.data["live_pr_after"]["head"]["sha"] = "c" * 40
        self.deny("PR changed during provider readback")

    def test_pr_number_changed_rejected(self):
        self.data["live_pr_after"]["number"] = 5
        self.deny("PR changed during provider readback")

    def test_pr_base_ref_wrong_rejected(self):
        for key in ("live_pr_before", "live_pr_after"):
            self.data[key]["base"]["ref"] = "dev"
        self.deny("unexpected PR identity")

    def test_pr_base_repository_wrong_rejected(self):
        for key in ("live_pr_before", "live_pr_after"):
            self.data[key]["base"]["repo"]["full_name"] = "someone/else"
        self.deny("unexpected PR identity")

    def test_draft_pr_does_not_gain_approval(self):
        for key in ("live_pr_before", "live_pr_after"):
            self.data[key]["draft"] = True
        self.deny("unexpected PR identity")

    def test_closed_pr_not_accepted(self):
        for key in ("live_pr_before", "live_pr_after"):
            self.data[key]["state"] = "closed"
        self.deny("unexpected PR identity")

    def test_wrong_pr_repository_option_rejected(self):
        self.data["repository"] = "other/repo"
        self.deny("unexpected repository")

    def test_missing_check_app_metadata_fails_closed(self):
        del self.data["check_run_by_id"]["app"]
        self.deny("check run readback is incomplete")

    def test_check_list_missing_all_results_rejected(self):
        self.data["check_run_list"] = {"total_count": 1, "check_runs": []}
        self.deny("incomplete or ambiguous")

    def test_check_list_over_1000_rejected(self):
        self.data["check_run_list"]["total_count"] = 1001
        self.deny("incomplete or ambiguous")

    def test_check_list_duplicate_id_rejected(self):
        self.data["check_run_list"]["check_runs"].append(
            copy.deepcopy(self.data["check_run_list"]["check_runs"][0]))
        self.data["check_run_list"]["total_count"] = 2
        self.deny("duplicate or invalid check run ID")

    def test_check_list_duplicate_external_id_rejected(self):
        second = copy.deepcopy(self.data["check_run_by_id"])
        second["id"] = 11223345
        self.data["check_run_list"]["check_runs"].append(second)
        self.data["check_run_list"]["total_count"] = 2
        self.deny("zero or ambiguous matching")

    def test_check_list_stale_conclusion_rejected(self):
        self.data["check_run_list"]["check_runs"][0]["conclusion"] = "failure"
        self.deny("list and detail")

    def test_check_list_stale_head_rejected(self):
        self.data["check_run_list"]["check_runs"][0]["head_sha"] = "d" * 40
        self.deny("zero or ambiguous matching")

    def test_check_id_boolean_rejected(self):
        self.data["check_run_by_id"]["id"] = True
        self.deny("check run head/source")

    def test_check_list_total_count_boolean_rejected(self):
        self.data["check_run_list"]["total_count"] = True
        self.deny("incomplete or ambiguous")

    def test_malformed_api_response_rejected(self):
        self.data["check_run_list"]["check_runs"].append(None)
        self.data["check_run_list"]["total_count"] = 2
        self.deny("malformed check run")

    def test_reconciliation_hold_can_be_candidate_only(self):
        self.data["local_intent"]["status"] = "RECONCILIATION_HOLD"
        r = compare_check_readback(**self.data).as_dict()
        self.assertFalse(r["api_authenticated"])
        self.assertEqual(r["status"],
                         "SYNTHETIC_MATCH_UNTRUSTED_NOT_AUTHORIZED")


if __name__ == "__main__":
    unittest.main()
