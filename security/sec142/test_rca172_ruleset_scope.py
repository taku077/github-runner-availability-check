"""RCA172: avoid declaring unscoped PR branches protected or actor known."""
import unittest
import rca172_ruleset_scope as m

def example():
    return {
        "repository": {"full_name": m.REPO, "default_branch": "main"},
        "all_rulesets": [{"id": 27806733, "target": "branch", "enforcement": "active"}],
        "ruleset": {"id": 27806733, "target": "branch", "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"],
                                                "exclude": []}},
                    "rules": [{"type": "pull_request",
                               "parameters": {"required_approving_review_count": 0}}]},
        "pr4": {"number": 4, "head": {
                    "ref": "dev/sec142-external-gate-prototype",
                    "repo": {"full_name": m.REPO}}, "base": {"ref": "main"}},
        "pr5": {"number": 5, "head": {
                    "ref": "dev/pcfm-ops160-offline-evtx-reader",
                    "repo": {"full_name": m.REPO}}, "base": {"ref": "main"}},
    }

class ScopeTest(unittest.TestCase):
    def setUp(self):
        self.data = example()
    def assess(self):
        return m.scope_assessment(self.data, "2026-11-24T02:30:00+09:00".replace("+09:00", "+00:00"))
    def test_main_only_scope(self):
        r = self.assess()
        self.assertTrue(r["main_within_this_ruleset"])
        self.assertFalse(r["draft_pr_branches"]["4"]["within_this_default_only_ruleset"])
        self.assertFalse(r["draft_pr_branches"]["5"]["within_this_default_only_ruleset"])
    def test_no_runtime_security_claim(self):
        r = self.assess()
        self.assertEqual(r["native_chatgpt_direct_write_denied"], "NOT_ESTABLISHED")
        self.assertEqual(r["independent_external_writer"], "NOT_IMPLEMENTED")
        self.assertEqual(r["independent_user_or_third_party_attribution"], "UNDETERMINED")
    def test_more_rulesets_is_unknown_not_unprotected(self):
        self.data["all_rulesets"].append({"id": 99, "target": "branch", "enforcement": "active"})
        with self.assertRaisesRegex(m.ScopeError, "UNDETERMINED"):
            self.assess()
    def test_incomplete_pagination_is_unknown(self):
        self.data["all_rulesets"] = [dict(self.data["all_rulesets"][0]) for _ in range(100)]
        with self.assertRaisesRegex(m.ScopeError, "INCOMPLETE"):
            self.assess()
    def test_branch_glob_is_not_interpreted_as_default_only(self):
        self.data["ruleset"]["conditions"]["ref_name"]["include"] = ["~ALL"]
        with self.assertRaisesRegex(m.ScopeError, "NON_DEFAULT_ONLY"):
            self.assess()
    def test_fork_cannot_claim_same_repo_coverage(self):
        self.data["pr4"]["head"]["repo"]["full_name"] = "someone/else"
        with self.assertRaisesRegex(m.ScopeError, "UNEXPECTED_PR_BRANCH"):
            self.assess()
    def test_denied_endpoint_before_network(self):
        def trap(*args, **kwargs):
            raise AssertionError("unexpected network")
        for path in ("/actions/runs", "/rulesets/2", "/repos/private", "https://evil.invalid"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(m.ScopeError, "NON_ALLOWLISTED"):
                    m.public_get(path, opener=trap)
    def test_invalid_default_ref_not_silent(self):
        self.data["repository"]["default_branch"] = "other"
        with self.assertRaisesRegex(m.ScopeError, "DEFAULT_BRANCH"):
            self.assess()
    def test_owner_approval_not_simulated(self):
        self.assertFalse(self.assess()["owner_confirmation_requested"])

if __name__ == "__main__":
    unittest.main()
