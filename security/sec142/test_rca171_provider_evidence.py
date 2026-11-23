"""RCA171 no approval theatre: fail-closed facts and never invent actor identity."""
import unittest
import rca171_provider_evidence as p

def sample():
    commits={}
    for i,sha in enumerate(p.CHAIN):
        commits[sha]={"sha":sha,"parents":[{"sha":p.MAIN if i==0 else p.CHAIN[i-1]}],
                      "author":{"login":"taku077"},
                      "commit":{"committer":{"date":"2026-11-23T11:28:36Z"},
                                "verification":{"verified":False,"reason":"unsigned"}}}
    commits[p.PROBE]={"sha":p.PROBE,
        "parents":[{"sha":"1961d604fe6a608227c0a54720f08e317ad8c53e"}],
        "commit":{"committer":{"date":"2026-11-23T12:43:41Z"},
                  "verification":{"verified":False,"reason":"unsigned"}}}
    return {"commits":commits,"pr4":{"number":4,"base":{"ref":"main"},
             "head":{"sha":p.PROBE},"draft":True},
            "pr5":{"number":5,"base":{"ref":"main"},
             "head":{"sha":p.CHAIN[-1]},"draft":True},
            "reviews4":[],"reviews5":[],
            "ruleset":{"id":27806733,"rules":[{"type":"pull_request",
                       "parameters":{"required_approving_review_count":0}}]}}

class ProviderTests(unittest.TestCase):
    def setUp(self): self.r=sample()
    def report(self): return p.summarize(self.r,"2026-11-24T00:00:00Z")

    def test_six_git_objects(self):
        self.assertEqual(len(self.report()["pr5_historical_git_chain"]),6)
    def test_unproved_attribution(self):
        self.r["commits"][p.CHAIN[-1]]["actor_is_bot"]=False
        self.assertEqual(self.report()["limits"]["ai_vs_human_vs_third_party"],"UNDETERMINED")
    def test_fake_request_id_never_promoted(self):
        self.r["commits"][p.CHAIN[0]]["request_id"]="claimed"
        self.assertEqual(self.report()["limits"]["authenticated_request_id"],"NOT_ACQUIRED")
    def test_bad_parent_denied(self):
        self.r["commits"][p.CHAIN[3]]["parents"][0]["sha"]=p.MAIN
        with self.assertRaisesRegex(p.EvidenceError,"PARENT_CHAIN"): self.report()
    def test_bad_commit_denied(self):
        self.r["commits"][p.CHAIN[0]]["sha"]="0"*40
        with self.assertRaisesRegex(p.EvidenceError,"SHA_MISMATCH"): self.report()
    def test_missing_signature_status_denied(self):
        del self.r["commits"][p.CHAIN[0]]["commit"]["verification"]
        with self.assertRaisesRegex(p.EvidenceError,"VERIFICATION"): self.report()
    def test_unsigned_not_identity(self):
        self.assertFalse(self.report()["limits"]["signature_or_review_proves_person_identity"])
    def test_review_not_owner_consent(self):
        self.r["reviews5"]=[{"state":"APPROVED","user":{"login":"someone"}}]
        self.assertEqual(self.report()["current_pr_metadata"]["5"]["review_count_at_query"],1)
        self.assertEqual(self.report()["limits"]["human_consent"],"NOT_ATTESTED")
    def test_drift_is_observed(self):
        self.r["pr5"]["head"]["sha"]="0"*40
        self.assertFalse(self.report()["current_pr_metadata"]["5"]["case_head_unchanged"])
    def test_untrusted_url_no_network(self):
        def fail(*a,**kw): raise AssertionError("NETWORK")
        with self.assertRaisesRegex(p.EvidenceError,"NON_ALLOWLISTED"):
            p.get_public_json("/actions/runs/123",opener=fail)
    def test_naive_timestamp_denied(self):
        self.r["commits"][p.CHAIN[0]]["commit"]["committer"]["date"]="2026-11-23T11:28:36"
        with self.assertRaisesRegex(p.EvidenceError,"NON_UTC"): self.report()
    def test_no_sensitive_git_fields_emitted(self):
        self.r["commits"][p.CHAIN[0]]["author"]["email"]="private@example.invalid"
        self.assertNotIn("private@example.invalid",str(self.report()))
        self.assertEqual(self.report()["network_scope"],"PUBLIC_GITHUB_GET_ONLY")

if __name__=="__main__": unittest.main()
