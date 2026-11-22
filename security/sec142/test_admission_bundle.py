"""SEC153: complete offline cross-snapshot non-authorization matrix.

No live tokens, HTTP, GitHub App or verified independent human reviewers.
"""
import copy
import unittest
from datetime import timedelta

from admission_bundle import compare_synthetic_admission_bundle
from test_prepost_consistency import fixture as app_fixture
from test_review_evidence import fixture as review_fixture, HEAD, OLD
from trusted_check_policy import Rejected


def fixture():
    app = app_fixture()
    review = review_fixture()
    app["expected_pr_number"] = review["pr_number"]
    app["started_at_utc"] = review["started_at_utc"] + timedelta(seconds=5)
    app["finished_at_utc"] = review["started_at_utc"] + timedelta(seconds=15)
    for name in ("pr_before", "pr_after"):
        app[name]["number"] = review["pr_number"]
        app[name]["user"] = copy.deepcopy(review["author"])
    return {"app_window": app, "review_window": review}


def change(data, *path, value):
    item = data
    for p in path[:-1]:
        item = item[p]
    item[path[-1]] = value


def app_receipt(data, kind, field, value):
    change(data, "app_window", "post_receipts", kind, "body", field,
           value=value)


class AdmissionBundleTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def denied(self):
        with self.assertRaises(Rejected):
            compare_synthetic_admission_bundle(**self.f)

    def test_consistent_fabricated_bundle_is_never_authorized(self):
        result = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.assertEqual(result["status"], "SYNTHETIC_BUNDLE_NOT_AUTHORIZED")
        self.assertEqual(result["reviewer_ids"], [222])
        self.assertEqual(result["review_ids"], [1])
        self.assertEqual(result["head_sha"], HEAD)
        self.assertEqual(len(result["metadata_sha256"]), 64)
        for name in ("digest_is_signature", "api_authenticated",
                     "reviewer_human_independence_verified",
                     "operator_authorized", "ruleset_enforcement_verified",
                     "check_written", "merge_authorized"):
            self.assertFalse(result[name], name)

    def test_repeated_same_fabricated_input_has_same_digest(self):
        a = compare_synthetic_admission_bundle(**self.f).as_dict()
        b = compare_synthetic_admission_bundle(**copy.deepcopy(self.f)).as_dict()
        self.assertEqual(a["metadata_sha256"], b["metadata_sha256"])

    def test_digest_changes_with_valid_check_window(self):
        a = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.f["app_window"]["finished_at_utc"] += timedelta(seconds=1)
        b = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.assertNotEqual(a["metadata_sha256"], b["metadata_sha256"])
        self.assertFalse(b["operator_authorized"])

    def test_duplicate_identical_forged_claim_cannot_grant_approval(self):
        self.f["review_window"]["allowed_reviewers"]["222"]["permission"] = (
            "admin")
        v = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.assertFalse(v["merge_authorized"])
        self.assertFalse(v["reviewer_human_independence_verified"])

    def test_forged_matching_user_account_proves_nothing(self):
        for name in ("pr_before", "pr_after"):
            self.f["app_window"][name]["user"]["login"] = "pr-author"
        result = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.assertEqual(result["status"], "SYNTHETIC_BUNDLE_NOT_AUTHORIZED")

    def test_no_github_reviewers_denied(self):
        for key in ("pages_before", "pages_after"):
            self.f["review_window"][key][0]["body"] = []
        self.denied()

    def test_current_public_pr4_draft_is_not_accepted(self):
        for name in ("pr_before", "pr_after"):
            self.f["app_window"][name]["draft"] = True
        self.denied()

    def test_review_readback_must_surround_check(self):
        self.f["review_window"]["started_at_utc"] += timedelta(seconds=6)
        self.denied()

    def test_review_after_check_completion_denied(self):
        self.f["review_window"]["finished_at_utc"] -= timedelta(seconds=16)
        self.denied()

    def test_pr_changed_during_check_denied(self):
        self.f["app_window"]["pr_after"]["head"]["sha"] = OLD
        self.denied()

    def test_bundle_author_is_pr_submitter_not_commit_author(self):
        self.f["review_window"]["author"]["login"] = "other"
        self.denied()


NEGATIVE_CASES = [
    ("extra_app_claim", lambda f: change(f,"app_window","operator_attested",value=True)),
    ("extra_review_claim", lambda f: change(f,"review_window","independent_operator_verified",value=True)),
    ("missing_app_key", lambda f: f["app_window"].pop("pinned_app_id")),
    ("missing_review_key", lambda f: f["review_window"].pop("pages_after")),
    ("app_window_not_dict", lambda f: change(f,"app_window",value=None)),
    ("review_window_not_dict", lambda f: change(f,"review_window",value=[])),
    ("pr_before_not_dict", lambda f: change(f,"app_window","pr_before",value=None)),
    ("pr_after_not_dict", lambda f: change(f,"app_window","pr_after",value={})),
    ("before_author_missing", lambda f: f["app_window"]["pr_before"].pop("user")),
    ("after_author_missing", lambda f: f["app_window"]["pr_after"].pop("user")),
    ("before_author_id_bad", lambda f: change(f,"app_window","pr_before","user","id",value="100")),
    ("before_author_id_bool", lambda f: change(f,"app_window","pr_before","user","id",value=True)),
    ("before_author_login_bad", lambda f: change(f,"app_window","pr_before","user","login",value="")),
    ("before_author_bot", lambda f: change(f,"app_window","pr_before","user","type",value="Bot")),
    ("after_author_id_change", lambda f: change(f,"app_window","pr_after","user","id",value=333)),
    ("after_author_login_change", lambda f: change(f,"app_window","pr_after","user","login",value="other")),
    ("review_author_id_change", lambda f: change(f,"review_window","author","id",value=333)),
    ("review_author_login_change", lambda f: change(f,"review_window","author","login",value="other")),
    ("review_number_changed", lambda f: change(f,"review_window","pr_number",value=43)),
    ("review_number_bool", lambda f: change(f,"review_window","pr_number",value=True)),
    ("app_number_changed", lambda f: change(f,"app_window","expected_pr_number",value=43)),
    ("app_number_bool", lambda f: change(f,"app_window","expected_pr_number",value=True)),
    ("review_head_changed", lambda f: change(f,"review_window","head_sha",value=OLD)),
    ("app_intent_head_changed", lambda f: change(f,"app_window","local_intent","head_sha",value=OLD)),
    ("app_intent_missing", lambda f: change(f,"app_window","local_intent",value=None)),
    ("app_pr_head_id_changed", lambda f: change(f,"app_window","pr_before","head","repo","id",value=1)),
    ("app_pr_head_name_changed", lambda f: change(f,"app_window","pr_before","head","repo","full_name",value="someone/else")),
    ("app_pr_base_changed", lambda f: change(f,"app_window","pr_after","base","sha",value=OLD)),
    ("app_pr_closed", lambda f: change(f,"app_window","pr_after","state",value="closed")),
    ("app_pr_merged", lambda f: change(f,"app_window","pr_after","merged",value=True)),
    ("app_pr_draft", lambda f: change(f,"app_window","pr_before","draft",value=True)),
    ("app_pr_user_wrong_type", lambda f: change(f,"app_window","pr_before","user","type",value="Bot")),
    ("app_pr_user_none", lambda f: change(f,"app_window","pr_before","user",value=None)),
    ("app_start_after_review_end", lambda f: change(f,"app_window","started_at_utc",value=f["review_window"]["finished_at_utc"] + timedelta(seconds=1))),
    ("app_end_after_review_end", lambda f: change(f,"app_window","finished_at_utc",value=f["review_window"]["finished_at_utc"] + timedelta(seconds=1))),
    ("review_start_after_app_start", lambda f: change(f,"review_window","started_at_utc",value=f["app_window"]["started_at_utc"]+timedelta(seconds=1))),
    ("review_finish_before_app_finish", lambda f: change(f,"review_window","finished_at_utc",value=f["app_window"]["finished_at_utc"]-timedelta(seconds=1))),
    ("review_start_no_timezone", lambda f: change(f,"review_window","started_at_utc",value=f["review_window"]["started_at_utc"].replace(tzinfo=None))),
    ("app_end_no_timezone", lambda f: change(f,"app_window","finished_at_utc",value=f["app_window"]["finished_at_utc"].replace(tzinfo=None))),
    ("app_reverse_window", lambda f: change(f,"app_window","finished_at_utc",value=f["app_window"]["started_at_utc"]-timedelta(seconds=1))),
    ("review_reverse_window", lambda f: change(f,"review_window","finished_at_utc",value=f["review_window"]["started_at_utc"]-timedelta(seconds=1))),
    ("app_installation_suspended", lambda f: app_receipt(f,"installation","suspended_at","2026-11-23T00:15:10Z")),
    ("app_scope_too_broad", lambda f: app_receipt(f,"installation","repository_selection","all")),
    ("app_wrong_id", lambda f: app_receipt(f,"app","id",987655)),
    ("app_wrong_repo_owner", lambda f: change(f,"app_window","post_receipts","repositories","body","repositories",0,"owner","id",value=1)),
    ("app_expired_token", lambda f: app_receipt(f,"scoped_token_metadata","expires_at","2026-11-23T00:16:00Z")),
    ("app_extra_permission", lambda f: change(f,"app_window","post_receipts","app","body","permissions","contents",value="write")),
    ("app_private_key_in_input", lambda f: app_receipt(f,"app","private_key","THIS_IS_NOT_A_REAL_KEY")),
    ("app_bad_pin", lambda f: change(f,"app_window","pinned_app_id",value=15368)),
    ("app_wrong_check_source", lambda f: change(f,"app_window","check_run_by_id","app","id",value=15368)),
    ("app_check_failed", lambda f: change(f,"app_window","check_run_by_id","conclusion",value="failure")),
    ("app_check_wrong_head", lambda f: change(f,"app_window","check_run_by_id","head_sha",value=OLD)),
    ("app_check_wrong_intent", lambda f: change(f,"app_window","check_run_by_id","external_id",value="wrong")),
    ("app_missing_check_pages", lambda f: change(f,"app_window","page_responses",value=[])),
    ("app_check_latest_filter", lambda f: change(f,"app_window","page_responses",0,"request_url",value=f["app_window"]["page_responses"][0]["request_url"].replace("filter=all","filter=latest"))),
    ("review_approval_old_sha", lambda f: change(f,"review_window","pages_before",0,"body",0,"commit_id",value=OLD)),
    ("review_approval_dismissed", lambda f: change(f,"review_window","pages_after",0,"body",0,"state",value="DISMISSED")),
    ("review_approval_removed", lambda f: change(f,"review_window","pages_after",0,"body",value=[])),
    ("review_approval_pending", lambda f: change(f,"review_window","pages_after",0,"body",0,"state",value="PENDING")),
    ("review_approval_wrong_user", lambda f: change(f,"review_window","pages_after",0,"body",0,"user","id",value=444)),
    ("review_author_self_approval", lambda f: change(f,"review_window","allowed_reviewers",value={"100":{"id":100,"login":"pr-author","type":"User","permission":"admin"}})),
    ("review_pusher_approval", lambda f: change(f,"review_window","allowed_reviewers",value={"101":{"id":101,"login":"last-pusher","type":"User","permission":"write"}})),
    ("review_roster_unprivileged", lambda f: change(f,"review_window","allowed_reviewers","222","permission",value="read")),
    ("review_roster_wrong_id", lambda f: change(f,"review_window","allowed_reviewers","222","id",value=999)),
    ("review_required_two_without_quorum", lambda f: change(f,"review_window","required_approvals",value=2)),
    ("review_last_push_after_review", lambda f: change(f,"review_window","last_push_at_utc",value="2026-11-23T00:12:00Z")),
    ("review_last_push_future", lambda f: change(f,"review_window","last_push_at_utc",value="2026-11-23T00:16:00Z")),
    ("review_page_status_403", lambda f: change(f,"review_window","pages_after",0,"status_code",value=403)),
    ("review_page_host_spoof", lambda f: change(f,"review_window","pages_before",0,"request_url",value="https://attacker.example")),
]
for name, mutate in NEGATIVE_CASES:
    def make_test(m=mutate):
        def test(self):
            self.f = fixture()
            m(self.f)
            self.denied()
        return test
    setattr(AdmissionBundleTests, "test_matrix_" + name, make_test())



class BundleSecretBoundaryTests(unittest.TestCase):
    """The bundle must reject credential-shaped fields anywhere in its tree."""

    def setUp(self):
        self.f = fixture()

    def denied(self):
        with self.assertRaises(Rejected):
            compare_synthetic_admission_bundle(**self.f)

    def test_token_hidden_under_pr_user_rejected(self):
        self.f["app_window"]["pr_before"]["user"]["token"] = "DUMMY"
        self.denied()

    def test_token_hidden_under_review_rejected(self):
        self.f["review_window"]["pages_after"][0]["body"][0][
            "access_token"] = "DUMMY"
        self.denied()

    def test_jwt_hidden_under_reviewer_roster_rejected(self):
        self.f["review_window"]["allowed_reviewers"]["222"][
            "jwt"] = "DUMMY"
        self.denied()

    def test_client_secret_under_last_pusher_rejected(self):
        self.f["review_window"]["last_pusher"]["client_secret"] = "DUMMY"
        self.denied()

    def test_password_under_local_intent_rejected(self):
        self.f["app_window"]["local_intent"]["password"] = "DUMMY"
        self.denied()

    def test_pem_under_check_detail_rejected(self):
        self.f["app_window"]["check_run_by_id"]["pem"] = "DUMMY"
        self.denied()

    def test_authorization_header_under_check_page_rejected(self):
        self.f["app_window"]["page_responses"][0]["headers"][
            "authorization"] = "DUMMY"
        self.denied()

    def test_private_key_nested_in_app_metadata_rejected(self):
        self.f["app_window"]["pre_receipts"]["app"]["body"][
            "private_key"] = "DUMMY"
        self.denied()

    def test_synthetic_verified_flag_in_review_cannot_authorize(self):
        for name in ("pages_before", "pages_after"):
            self.f["review_window"][name][0]["body"][0][
                "independently_verified"] = True
        r = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.assertFalse(r["operator_authorized"])
        self.assertFalse(r["merge_authorized"])
        self.assertFalse(r["api_authenticated"])

    def test_review_sender_claim_cannot_attest_true_identity(self):
        self.f["review_window"]["allowed_reviewers"]["222"][
            "synthetic_verified_human"] = True
        result = compare_synthetic_admission_bundle(**self.f).as_dict()
        self.assertFalse(result["reviewer_human_independence_verified"])

    def test_pr_head_record_missing_rejected(self):
        self.f["app_window"]["pr_before"]["head"] = None
        self.denied()

    def test_pr_head_repo_record_missing_rejected(self):
        self.f["app_window"]["pr_before"]["head"]["repo"] = None
        self.denied()

    def test_pr_head_repo_id_bool_rejected(self):
        self.f["app_window"]["pr_before"]["head"]["repo"]["id"] = True
        self.denied()

    def test_missing_local_intent_is_controlled_rejection(self):
        self.f["app_window"]["local_intent"] = None
        self.denied()

    def test_wrong_base_after_synthetic_read_denied(self):
        self.f["app_window"]["pr_after"]["base"]["sha"] = "f" * 40
        self.denied()

    def test_author_changed_during_synthetic_read_denied(self):
        self.f["app_window"]["pr_after"]["user"]["id"] = 999
        self.denied()

    def test_last_pusher_equals_rostered_reviewer_denied(self):
        self.f["review_window"]["last_pusher"] = {
            "id": 222, "login": "human-reviewer", "type": "User"}
        self.denied()

if __name__ == "__main__":
    unittest.main()
