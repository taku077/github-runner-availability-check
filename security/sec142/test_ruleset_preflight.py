"""SEC154: current public Ruleset negative fixture + future all-green synthetic.

All structures are untrusted in-process JSON-like values, NOT authenticated
API evidence. The real PR #4 remains Draft with zero reviews.
"""
import copy
import unittest

from ruleset_preflight import audit_readonly_gate

REPO_ID = 1450293513
HEAD = "a" * 40
BASE = "b" * 40
APP = 987654  # invented App, no installation or protected private key


def live_shape():
    """Subset of publicly observed 2026-11-23 Ruleset 27806733 / PR #4."""
    return {
        "repository": {"id": REPO_ID,
                       "full_name": "taku077/github-runner-availability-check",
                       "owner": {"type": "User"}},
        "ruleset": {
            "id": 27806733, "name": "PCFM-Public-CI-Main-Protection",
            "target": "branch", "source_type": "Repository",
            "source": "taku077/github-runner-availability-check",
            "enforcement": "active", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"],
                                        "exclude": []}},
            "rules": [
                {"type": "non_fast_forward"},
                {"type": "deletion"},
                {"type": "pull_request", "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": False,
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": False}},
                {"type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": False,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [{
                        "context": "env003-main-rules",
                        "integration_id": 15368}]}}
            ]},
        "pull_request": {
            "number": 4, "state": "open", "draft": True, "merged": False,
            "user": {"id": 344928446, "login": "taku077"},
            "head": {"sha": HEAD, "repo": {"id": REPO_ID}},
            "base": {"sha": BASE, "ref": "main",
                     "repo": {"id": REPO_ID}}},
        "reviews": [],
        "check_run_list": {
            "total_count": 1, "check_runs": [{
                "id": 137305103835, "name":
                    "sec142-prototype-tests-not-a-required-gate",
                "app": {"id": 15368},
                "head_sha": HEAD, "status": "completed",
                "conclusion": "success"}]},
        "independently_pinned_app_id": None,
    }


def fantasy_green():
    f = live_shape()
    pull = next(z for z in f["ruleset"]["rules"]
                if z["type"] == "pull_request")["parameters"]
    pull.update({"required_approving_review_count": 1,
                 "dismiss_stale_reviews_on_push": True,
                 "require_last_push_approval": True,
                 "required_review_thread_resolution": True})
    checks = next(z for z in f["ruleset"]["rules"]
                  if z["type"] == "required_status_checks")["parameters"]
    checks["strict_required_status_checks_policy"] = True
    checks["required_status_checks"].append({
        "context": "pcfm-independent-admission",
        "integration_id": APP})
    f["pull_request"]["draft"] = False
    f["reviews"] = [{"id": 1, "state": "APPROVED",
                     "commit_id": HEAD, "user": {"id": 67890}}]
    f["check_run_list"]["total_count"] += 1
    f["check_run_list"]["check_runs"].append({
        "id": 99999, "name": "pcfm-independent-admission",
        "app": {"id": APP}, "head_sha": HEAD, "status": "completed",
        "conclusion": "success"})
    f["independently_pinned_app_id"] = APP
    return f


class RulesetPreflightTests(unittest.TestCase):
    def assertBlocked(self, fixture, *required):
        result = audit_readonly_gate(**fixture).as_dict()
        self.assertEqual(result["status"], "READONLY_PREFLIGHT_NOT_ACCEPTED")
        for item in required:
            self.assertIn(item, result["findings"])
        for field in ("source_is_independent",
                      "operator_identity_attested",
                      "reviewer_human_independence_attested",
                      "live_negative_merge_test_passed",
                      "api_transport_authenticated_by_separate_host",
                      "independent_enforcement_accepted", "check_written",
                      "merge_authorized", "production_deployed"):
            self.assertFalse(result[field], field)
        return result

    def test_actual_public_snapshot_is_blocked(self):
        self.assertBlocked(live_shape(),
                           "REVIEW_APPROVAL_MINIMUM_MISSING",
                           "INDEPENDENT_APP_NOT_PINNED",
                           "INDEPENDENT_CHECK_NOT_REQUIRED",
                           "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT",
                           "CURRENT_SHA_APPROVALS_NOT_OBSERVED",
                           "INDEPENDENT_CHECK_RUN_NOT_OBSERVED")

    def test_future_all_green_forged_json_still_untrusted(self):
        result = self.assertBlocked(
            fantasy_green(),
            "EXTERNAL_OPERATOR_AND_PROVIDER_AUTHENTICATION_NOT_PROVEN",
            "LIVE_REJECTION_TEST_NOT_PROVEN")
        self.assertEqual(len(result["findings"]), 2)

    def test_public_actions_check_success_not_independent(self):
        f = live_shape()
        f["check_run_list"]["check_runs"][0]["conclusion"] = "success"
        self.assertBlocked(f, "INDEPENDENT_CHECK_NOT_REQUIRED")

    def test_duplicate_status_context_rejected(self):
        f = fantasy_green()
        checks = f["ruleset"]["rules"][-1]["parameters"][
            "required_status_checks"]
        checks.append(copy.deepcopy(checks[-1]))
        self.assertBlocked(f, "INVALID_OR_DUPLICATE_REQUIRED_CHECK")

    def test_no_human_attestation_even_with_two_approvals(self):
        f = fantasy_green()
        f["reviews"].append({"id": 2, "state": "APPROVED",
                             "commit_id": HEAD, "user": {"id": 67891}})
        f["ruleset"]["rules"][2]["parameters"][
            "required_approving_review_count"] = 2
        self.assertBlocked(f, "EXTERNAL_OPERATOR_AND_PROVIDER_AUTHENTICATION_NOT_PROVEN")


def _change(root, *path, value):
    d = root
    for key in path[:-1]:
        d = d[key]
    d[path[-1]] = value


MUTANTS = [
    ("repo_id", lambda f: _change(f,"repository","id",value=1), "TARGET_REPOSITORY_NOT_VERIFIED"),
    ("repo_owner", lambda f: _change(f,"repository","owner","type",value="Organization"), "TARGET_REPOSITORY_NOT_VERIFIED"),
    ("repo_name", lambda f: _change(f,"repository","full_name",value="some/other"), "TARGET_REPOSITORY_NOT_VERIFIED"),
    ("ruleset_id", lambda f: _change(f,"ruleset","id",value=12), "RULESET_IDENTITY_NOT_VERIFIED"),
    ("ruleset_target", lambda f: _change(f,"ruleset","target",value="push"), "RULESET_IDENTITY_NOT_VERIFIED"),
    ("ruleset_source", lambda f: _change(f,"ruleset","source",value="someone/else"), "RULESET_IDENTITY_NOT_VERIFIED"),
    ("ruleset_disabled", lambda f: _change(f,"ruleset","enforcement",value="disabled"), "RULESET_NOT_ACTIVE"),
    ("ruleset_evaluate", lambda f: _change(f,"ruleset","enforcement",value="evaluate"), "RULESET_NOT_ACTIVE"),
    ("branch_scope", lambda f: _change(f,"ruleset","conditions","ref_name","include",value=["refs/heads/dev"]), "DEFAULT_BRANCH_SCOPE_UNVERIFIED"),
    ("branch_exclusion", lambda f: _change(f,"ruleset","conditions","ref_name","exclude",value=["main"]), "DEFAULT_BRANCH_SCOPE_UNVERIFIED"),
    ("bypass_admin", lambda f: _change(f,"ruleset","bypass_actors",value=[{"actor_id":1}]), "RULESET_BYPASS_NOT_EXCLUDED"),
    ("bypass_missing", lambda f: f["ruleset"].pop("bypass_actors"), "RULESET_BYPASS_NOT_EXCLUDED"),
    ("no_rules", lambda f: _change(f,"ruleset","rules",value=[]), "RULE_DEFINITIONS_MISSING"),
    ("duplicate_pull_rule", lambda f: f["ruleset"]["rules"].append(copy.deepcopy(f["ruleset"]["rules"][2])), "AMBIGUOUS_RULE_DEFINITIONS"),
    ("no_nonfastforward", lambda f: f["ruleset"]["rules"].pop(0), "REQUIRED_BRANCH_RULE_MISSING"),
    ("no_deletion", lambda f: f["ruleset"]["rules"].pop(1), "REQUIRED_BRANCH_RULE_MISSING"),
    ("no_pull_rule", lambda f: f["ruleset"]["rules"].pop(2), "REQUIRED_BRANCH_RULE_MISSING"),
    ("no_check_rule", lambda f: f["ruleset"]["rules"].pop(3), "REQUIRED_BRANCH_RULE_MISSING"),
    ("required_count_zero", lambda f: _change(f,"ruleset","rules",2,"parameters","required_approving_review_count",value=0), "REVIEW_APPROVAL_MINIMUM_MISSING"),
    ("required_count_bool", lambda f: _change(f,"ruleset","rules",2,"parameters","required_approving_review_count",value=True), "REVIEW_APPROVAL_MINIMUM_MISSING"),
    ("required_last_push_false", lambda f: _change(f,"ruleset","rules",2,"parameters","require_last_push_approval",value=False), "LAST_PUSH_INDEPENDENT_APPROVAL_NOT_REQUIRED"),
    ("stale_not_dismissed", lambda f: _change(f,"ruleset","rules",2,"parameters","dismiss_stale_reviews_on_push",value=False), "STALE_REVIEW_DISMISSAL_NOT_ENFORCED"),
    ("review_thread_not_required", lambda f: _change(f,"ruleset","rules",2,"parameters","required_review_thread_resolution",value=False), "REVIEW_THREAD_RESOLUTION_NOT_REQUIRED"),
    ("strict_not_required", lambda f: _change(f,"ruleset","rules",3,"parameters","strict_required_status_checks_policy",value=False), "STATUS_CHECK_BRANCH_FRESHNESS_NOT_REQUIRED"),
    ("check_create_bypass", lambda f: _change(f,"ruleset","rules",3,"parameters","do_not_enforce_on_create",value=True), "STATUS_CHECK_ENFORCEMENT_SCOPE_WEAK"),
    ("required_missing_independent", lambda f: _change(f,"ruleset","rules",3,"parameters","required_status_checks",value=[]), "INDEPENDENT_CHECK_NOT_REQUIRED"),
    ("wrong_app_in_ruleset", lambda f: _change(f,"ruleset","rules",3,"parameters","required_status_checks",1,"integration_id",value=15368), "INDEPENDENT_CHECK_SOURCE_NOT_PINNED"),
    ("wrong_app_in_check", lambda f: _change(f,"check_run_list","check_runs",1,"app","id",value=15368), "INDEPENDENT_CHECK_RUN_SOURCE_OR_STATE_UNVERIFIED"),
    ("wrong_check_sha", lambda f: _change(f,"check_run_list","check_runs",1,"head_sha",value="c"*40), "INDEPENDENT_CHECK_RUN_SOURCE_OR_STATE_UNVERIFIED"),
    ("check_failed", lambda f: _change(f,"check_run_list","check_runs",1,"conclusion",value="failure"), "INDEPENDENT_CHECK_RUN_SOURCE_OR_STATE_UNVERIFIED"),
    ("check_running", lambda f: _change(f,"check_run_list","check_runs",1,"status",value="in_progress"), "INDEPENDENT_CHECK_RUN_SOURCE_OR_STATE_UNVERIFIED"),
    ("app_unpinned", lambda f: _change(f,"independently_pinned_app_id",value=None), "INDEPENDENT_APP_NOT_PINNED"),
    ("app_pinned_actions", lambda f: _change(f,"independently_pinned_app_id",value=15368), "INDEPENDENT_APP_NOT_PINNED"),
    ("app_pinned_bool", lambda f: _change(f,"independently_pinned_app_id",value=True), "INDEPENDENT_APP_NOT_PINNED"),
    ("pr_draft", lambda f: _change(f,"pull_request","draft",value=True), "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT"),
    ("pr_closed", lambda f: _change(f,"pull_request","state",value="closed"), "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT"),
    ("pr_merged", lambda f: _change(f,"pull_request","merged",value=True), "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT"),
    ("pr_wrong_head_id", lambda f: _change(f,"pull_request","head","repo","id",value=2), "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT"),
    ("pr_wrong_base_id", lambda f: _change(f,"pull_request","base","repo","id",value=3), "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT"),
    ("pr_bad_sha", lambda f: _change(f,"pull_request","head","sha",value="short"), "PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT"),
    ("no_review", lambda f: _change(f,"reviews",value=[]), "CURRENT_SHA_APPROVALS_NOT_OBSERVED"),
    ("review_old_head", lambda f: _change(f,"reviews",0,"commit_id",value=BASE), "CURRENT_SHA_APPROVALS_NOT_OBSERVED"),
    ("review_self", lambda f: _change(f,"reviews",0,"user","id",value=344928446), "CURRENT_SHA_APPROVALS_NOT_OBSERVED"),
    ("review_pending", lambda f: _change(f,"reviews",0,"state",value="PENDING"), "CURRENT_SHA_APPROVALS_NOT_OBSERVED"),
    ("check_count_mismatch", lambda f: _change(f,"check_run_list","total_count",value=3), "CHECK_RUN_COLLECTION_INCOMPLETE"),
    ("check_duplicate_id", lambda f: _change(f,"check_run_list","check_runs",1,"id",value=137305103835), "CHECK_RUN_IDENTITY_AMBIGUOUS"),
    ("check_duplicate_name", lambda f: f["check_run_list"]["check_runs"].append(dict(f["check_run_list"]["check_runs"][1], id=22)), "INDEPENDENT_CHECK_RUN_NOT_OBSERVED"),
    ("check_none", lambda f: _change(f,"check_run_list","check_runs",value=[]), "CHECK_RUN_COLLECTION_INCOMPLETE"),
    ("check_not_dict", lambda f: _change(f,"check_run_list",value="untrusted"), "CHECK_RUN_COLLECTION_INCOMPLETE"),
]
for name, mutator, expected in MUTANTS:
    def make_test(m=mutator, reason=expected):
        def test(self):
            f = fantasy_green()
            m(f)
            self.assertBlocked(f, reason)
        return test
    setattr(RulesetPreflightTests, "test_mutation_" + name, make_test())


if __name__ == "__main__":
    unittest.main()
