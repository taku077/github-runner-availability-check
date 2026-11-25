"""SEC155: fail-closed SEC154 review-supersession and identity regression.

These are entirely synthetic API-shaped fixtures. Neither GitHub's effective
merge policy nor the human identity of a reviewer is attested by this module.
"""
import copy
import unittest

from ruleset_preflight import audit_readonly_gate
from test_ruleset_preflight import fantasy_green, HEAD, BASE


def later_review(rid, *, user_id=67890, state="APPROVED", sha=HEAD):
    return {
        "id": rid,
        "state": state,
        "commit_id": sha,
        "user": {"id": user_id, "type": "User"}
    }


class RulesetReviewHardeningTests(unittest.TestCase):
    def setUp(self):
        self.f = fantasy_green()

    def findings(self):
        res = audit_readonly_gate(**self.f).as_dict()
        self.assertEqual(res["status"], "READONLY_PREFLIGHT_NOT_ACCEPTED")
        self.assertFalse(res["merge_authorized"])
        self.assertFalse(res["independent_enforcement_accepted"])
        return set(res["findings"])

    def assertMissingApproval(self, *others):
        findings = self.findings()
        self.assertIn("CURRENT_SHA_APPROVALS_NOT_OBSERVED", findings)
        for other in others:
            self.assertIn(other, findings)

    def test_default_fake_green_still_cannot_authorize(self):
        self.assertEqual(self.findings(), {
            "EXTERNAL_OPERATOR_AND_PROVIDER_AUTHENTICATION_NOT_PROVEN",
            "LIVE_REJECTION_TEST_NOT_PROVEN"})

    def test_approval_followed_by_changes_requested_blocks(self):
        self.f["reviews"].append(
            later_review(2, state="CHANGES_REQUESTED"))
        self.assertMissingApproval("UNRESOLVED_CHANGE_REQUESTS")

    def test_approval_followed_by_comment_is_superseded(self):
        self.f["reviews"].append(later_review(2, state="COMMENTED"))
        self.assertMissingApproval()

    def test_approval_followed_by_dismissal_is_superseded(self):
        self.f["reviews"].append(later_review(2, state="DISMISSED"))
        self.assertMissingApproval()

    def test_approval_followed_by_old_commit_approval_fails(self):
        self.f["reviews"].append(later_review(2, sha=BASE))
        self.assertMissingApproval()

    def test_comment_then_current_approval_is_structurally_consistent(self):
        self.f["reviews"][0]["state"] = "COMMENTED"
        self.f["reviews"].append(later_review(2))
        self.assertNotIn("CURRENT_SHA_APPROVALS_NOT_OBSERVED",
                         self.findings())

    def test_current_approval_clears_same_reviewers_request_in_fixture(self):
        self.f["reviews"][0]["state"] = "CHANGES_REQUESTED"
        self.f["reviews"].append(later_review(2))
        found = self.findings()
        self.assertNotIn("UNRESOLVED_CHANGE_REQUESTS", found)
        self.assertNotIn("CURRENT_SHA_APPROVALS_NOT_OBSERVED", found)

    def test_stale_approval_cannot_clear_changes_requested(self):
        self.f["reviews"][0]["state"] = "CHANGES_REQUESTED"
        self.f["reviews"].append(later_review(2, sha=BASE))
        self.assertMissingApproval("UNRESOLVED_CHANGE_REQUESTS")

    def test_comment_does_not_clear_change_request(self):
        self.f["reviews"][0]["state"] = "CHANGES_REQUESTED"
        self.f["reviews"].append(later_review(2, state="COMMENTED"))
        self.assertMissingApproval("UNRESOLVED_CHANGE_REQUESTS")

    def test_dismissal_does_not_clear_change_request(self):
        self.f["reviews"][0]["state"] = "CHANGES_REQUESTED"
        self.f["reviews"].append(later_review(2, state="DISMISSED"))
        self.assertMissingApproval("UNRESOLVED_CHANGE_REQUESTS")

    def test_unresolved_request_from_other_reviewer_blocks_all(self):
        self.f["reviews"].append(later_review(
            2, user_id=77777, state="CHANGES_REQUESTED"))
        self.assertMissingApproval("UNRESOLVED_CHANGE_REQUESTS")

    def test_valid_two_distinct_reviewers_still_not_authority(self):
        self.f["reviews"].append(later_review(2, user_id=77777))
        self.f["ruleset"]["rules"][2]["parameters"][
            "required_approving_review_count"] = 2
        self.assertNotIn("CURRENT_SHA_APPROVALS_NOT_OBSERVED",
                         self.findings())

    def test_same_person_two_approvals_never_count_as_two_accounts(self):
        self.f["reviews"].append(later_review(2, user_id=67890))
        self.f["ruleset"]["rules"][2]["parameters"][
            "required_approving_review_count"] = 2
        self.assertMissingApproval()

    def test_duplicate_review_id_rejected(self):
        self.f["reviews"].append(later_review(1))
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_decreasing_review_id_rejected(self):
        self.f["reviews"][0]["id"] = 7
        self.f["reviews"].append(later_review(3))
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_nonpositive_review_id_rejected(self):
        self.f["reviews"][0]["id"] = 0
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_boolean_review_id_rejected(self):
        self.f["reviews"][0]["id"] = True
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_boolean_user_id_rejected(self):
        self.f["reviews"][0]["user"]["id"] = True
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_unknown_state_rejected(self):
        self.f["reviews"][0]["state"] = "PENDING"
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_nonhashable_state_rejected_without_unhandled_exception(self):
        self.f["reviews"][0]["state"] = ["APPROVED"]
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_empty_state_rejected(self):
        self.f["reviews"][0]["state"] = ""
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_missing_review_user_rejected(self):
        self.f["reviews"][0].pop("user")
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_non_dict_review_rejected(self):
        self.f["reviews"][0] = None
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_bad_commit_sha_rejected(self):
        self.f["reviews"][0]["commit_id"] = "bad"
        self.assertMissingApproval("REVIEW_HISTORY_AMBIGUOUS")

    def test_old_sha_approval_rejected(self):
        self.f["reviews"][0]["commit_id"] = BASE
        self.assertMissingApproval()

    def test_pr_author_self_approval_rejected(self):
        self.f["reviews"][0]["user"]["id"] = 344928446
        self.assertMissingApproval()

    def test_review_collector_not_proven_by_independent_flag(self):
        self.f["pull_request"]["user"]["trusted_operator"] = True
        res = audit_readonly_gate(**self.f).as_dict()
        self.assertFalse(res["operator_identity_attested"])
        self.assertFalse(res["api_transport_authenticated_by_separate_host"])

    def test_hypothetical_review_history_remains_readonly(self):
        result = audit_readonly_gate(**self.f).as_dict()
        for name in ("source_is_independent",
                     "reviewer_human_independence_attested",
                     "live_negative_merge_test_passed",
                     "check_written", "merge_authorized",
                     "production_deployed"):
            self.assertFalse(result[name], name)

    # SEC159: account-type labels are structure only, not human identity proof.
    # A missing/fake PR author ID previously caused the approval account to
    # be counted as independent even though self-approval could not be ruled out.
    def test_missing_pr_author_fails_closed(self):
        self.f["pull_request"].pop("user")
        self.assertMissingApproval("PR_AUTHOR_ID_NOT_VERIFIED")

    def test_pr_author_id_zero_fails_closed(self):
        self.f["pull_request"]["user"]["id"] = 0
        self.assertMissingApproval("PR_AUTHOR_ID_NOT_VERIFIED")

    def test_pr_author_id_boolean_fails_closed(self):
        self.f["pull_request"]["user"]["id"] = True
        self.assertMissingApproval("PR_AUTHOR_ID_NOT_VERIFIED")

    def test_pr_author_type_missing_fails_closed(self):
        self.f["pull_request"]["user"].pop("type")
        self.assertMissingApproval("PR_AUTHOR_ID_NOT_VERIFIED")

    def test_pr_author_bot_type_fails_closed(self):
        self.f["pull_request"]["user"]["type"] = "Bot"
        self.assertMissingApproval("PR_AUTHOR_ID_NOT_VERIFIED")

    def test_reviewer_type_missing_fails_closed(self):
        self.f["reviews"][0]["user"].pop("type")
        self.assertMissingApproval("REVIEW_ACTOR_TYPE_NOT_VERIFIED",
                                   "REVIEW_HISTORY_AMBIGUOUS")

    def test_reviewer_bot_type_fails_closed(self):
        self.f["reviews"][0]["user"]["type"] = "Bot"
        self.assertMissingApproval("REVIEW_ACTOR_TYPE_NOT_VERIFIED",
                                   "REVIEW_HISTORY_AMBIGUOUS")

    def test_reviewer_type_list_fails_closed(self):
        self.f["reviews"][0]["user"]["type"] = ["User"]
        self.assertMissingApproval("REVIEW_ACTOR_TYPE_NOT_VERIFIED",
                                   "REVIEW_HISTORY_AMBIGUOUS")

    def test_user_type_cannot_prove_human_separation(self):
        report = audit_readonly_gate(**self.f).as_dict()
        self.assertFalse(report["reviewer_human_independence_attested"])
        self.assertFalse(report["operator_identity_attested"])
        self.assertFalse(report["merge_authorized"])


if __name__ == "__main__":
    unittest.main()
