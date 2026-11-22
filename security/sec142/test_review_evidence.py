"""SEC152: offline GitHub review API pagination and supersession matrix.

All records and roles are invented synthetic fixtures; never an approval.
"""
import copy
import unittest
from datetime import datetime, timedelta, timezone

from review_evidence import (
    compare_review_history, read_review_pages, _url_page,
)
from trusted_check_policy import Rejected

HEAD = "a" * 40
OLD = "b" * 40
NOW = datetime(2026, 11, 23, 0, 15, tzinfo=timezone.utc)
OWNER = {"id": 100, "login": "pr-author", "type": "User"}
PUSHER = {"id": 101, "login": "last-pusher", "type": "User"}
REVIEWER = {"id": 222, "login": "human-reviewer", "type": "User",
            "permission": "write"}
REPO = "taku077/github-runner-availability-check"


def url(page):
    return (f"https://api.github.com/repos/{REPO}/pulls/42/reviews"
            f"?per_page=100&page={page}")


def review(rid=1, user=None, state="APPROVED",
           commit=HEAD, submitted="2026-11-23T00:10:00Z"):
    return {"id": rid, "user": copy.deepcopy(user or REVIEWER),
            "state": state, "commit_id": commit, "submitted_at": submitted}


def fixture():
    body = [review()]
    page = {"request_url": url(1), "status_code": 200,
            "headers": {"Link": ""}, "body": body}
    return {"pages_before": [copy.deepcopy(page)],
            "pages_after": [copy.deepcopy(page)],
            "pr_number": 42, "head_sha": HEAD,
            "author": copy.deepcopy(OWNER),
            "last_pusher": copy.deepcopy(PUSHER),
            "last_push_at_utc": "2026-11-23T00:01:00Z",
            "allowed_reviewers": {"222": copy.deepcopy(REVIEWER)},
            "required_approvals": 1,
            "started_at_utc": NOW,
            "finished_at_utc": NOW + timedelta(seconds=30)}


def multi_page():
    body = [
        review(rid=n, user={"id": 1000+n, "login": f"other-reviewer-{n}",
                            "type": "User"},
               state="COMMENTED", submitted="2026-11-23T00:09:00Z")
        for n in range(1, 101)
    ]
    body.append(review(rid=101))
    first = {"request_url": url(1), "status_code": 200,
             "headers": {"Link": (
                 f'<{url(2)}>; rel="next", <{url(2)}>; rel="last"')},
             "body": body[:100]}
    second = {"request_url": url(2), "status_code": 200,
              "headers": {"Link": (
                  f'<{url(1)}>; rel="first", <{url(1)}>; rel="prev"')},
              "body": body[100:]}
    return [first, second]


class ReviewEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def deny(self, fragment):
        with self.assertRaisesRegex(Rejected, fragment):
            compare_review_history(**self.f)

    def test_matching_review_is_untrusted(self):
        r = compare_review_history(**self.f).as_dict()
        self.assertEqual(r["status"], "SYNTHETIC_REVIEW_MATCH_NOT_AUTHORIZED")
        self.assertEqual(r["review_ids"], [1])
        self.assertEqual(r["reviewer_ids"], [222])
        self.assertFalse(r["reviews_provider_authenticated"])
        self.assertFalse(r["actor_independence_attested"])
        self.assertFalse(r["operator_authorized"])
        self.assertFalse(r["merge_authorized"])
        self.assertFalse(r["check_written"])

    def test_live_pr4_zero_review_fixture_denies(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"] = []
        self.deny("no submitted PR review")

    def test_two_page_review_inventory_candidate(self):
        self.f["pages_before"] = multi_page()
        self.f["pages_after"] = copy.deepcopy(self.f["pages_before"])
        r = compare_review_history(**self.f).as_dict()
        self.assertEqual(r["review_ids"], [101])
        self.assertFalse(r["operator_authorized"])

    def test_page_exactly_100_final_no_next(self):
        pages = multi_page()[:1]
        pages[0]["headers"] = {"Link": ""}
        self.assertEqual(len(read_review_pages(
            pages=pages, pr_number=42, observed_at_utc=NOW)), 100)

    def test_approved_then_commented_is_not_approval(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"].append(
                review(2, state="COMMENTED",
                       submitted="2026-11-23T00:11:00Z"))
        self.deny("no sufficient current distinct approvals")

    def test_approved_then_dismissed_is_not_approval(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"].append(
                review(2, state="DISMISSED",
                       submitted="2026-11-23T00:11:00Z"))
        self.deny("no sufficient current distinct approvals")

    def test_any_current_changes_requested_blocks(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"].append(
                review(2, user={"id": 876, "login": "other", "type": "User"},
                       state="CHANGES_REQUESTED",
                       submitted="2026-11-23T00:11:00Z"))
        self.deny("outstanding changes-requested review")

    def test_stale_review_sha_blocks(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"][0]["commit_id"] = OLD
        self.deny("stale approval")

    def test_post_review_push_blocks(self):
        self.f["last_push_at_utc"] = "2026-11-23T00:12:00Z"
        self.deny("stale approval")

    def test_at_push_timestamp_not_accepted(self):
        self.f["last_push_at_utc"] = "2026-11-23T00:10:00Z"
        self.deny("stale approval")

    def test_two_reviewers_distinct_approvals(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"].append(
                review(2, user={"id": 223, "login": "human-reviewer-2",
                                "type": "User"},
                       submitted="2026-11-23T00:11:00Z"))
        self.f["allowed_reviewers"]["223"] = {
            "id": 223, "login": "human-reviewer-2",
            "type": "User", "permission": "maintain"}
        self.f["required_approvals"] = 2
        r = compare_review_history(**self.f).as_dict()
        self.assertEqual(r["reviewer_ids"], [222, 223])
        self.assertFalse(r["merge_authorized"])

    def test_two_approvals_same_account_not_two(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"].append(
                review(2, submitted="2026-11-23T00:11:00Z"))
        self.f["allowed_reviewers"]["223"] = {
            "id": 223, "login": "human-reviewer-2",
            "type": "User", "permission": "write"}
        self.f["required_approvals"] = 2
        self.deny("no sufficient current distinct approvals")

    def test_author_not_eligible_to_review(self):
        self.f["allowed_reviewers"] = {
            "100": {"id": 100, "login": "pr-author",
                    "type": "User", "permission": "admin"}}
        self.deny("reviewer overlaps author")

    def test_last_pusher_not_eligible_to_review(self):
        self.f["allowed_reviewers"] = {
            "101": {"id": 101, "login": "last-pusher",
                    "type": "User", "permission": "write"}}
        self.deny("reviewer overlaps author")

    def test_review_history_changes_during_readback(self):
        self.f["pages_after"][0]["body"][0]["state"] = "COMMENTED"
        self.deny("PR review history changed")

    def test_latest_approval_supersedes_earlier_comment(self):
        for key in ("pages_before", "pages_after"):
            rows = self.f[key][0]["body"]
            rows[0]["state"] = "COMMENTED"
            rows.append(review(2, submitted="2026-11-23T00:11:00Z"))
        self.assertFalse(compare_review_history(**self.f).as_dict()[
            "operator_authorized"])

    def test_second_page_missing_is_denied(self):
        self.f["pages_before"] = multi_page()[:1]
        self.f["pages_after"] = copy.deepcopy(self.f["pages_before"])
        self.deny("unfetched PR-review continuation")

    def test_page_order_invalid(self):
        self.f["pages_before"] = multi_page()[::-1]
        self.f["pages_after"] = copy.deepcopy(self.f["pages_before"])
        self.deny("PR-review page failed or reordered")

    def test_stale_review_future_rejected(self):
        for key in ("pages_before", "pages_after"):
            self.f[key][0]["body"][0]["submitted_at"] = (
                "2026-11-23T00:16:00Z")
        self.deny("review submitted after observation")

    def test_non_utc_observation_rejected(self):
        self.f["finished_at_utc"] = NOW.astimezone(
            timezone(timedelta(hours=9)))
        self.deny("invalid PR-review observation window")


def _set(root, *path, value):
    cur = root
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value


# Table-driven negative fixtures are registered as distinct unittest methods.
# Each case has its own stable test name in GitHub CI output. Inputs synthetic.
CASES = [
    ("unknown_state", lambda f: _set(f, "pages_before", 0, "body", 0, "state", value="PENDING"), "unknown or unsubmitted"),
    ("bad_state_type", lambda f: _set(f, "pages_before", 0, "body", 0, "state", value=True), "unknown or unsubmitted"),
    ("review_id_bool", lambda f: _set(f, "pages_before", 0, "body", 0, "id", value=True), "invalid review record"),
    ("review_id_zero", lambda f: _set(f, "pages_before", 0, "body", 0, "id", value=0), "invalid review record"),
    ("review_bad_sha", lambda f: _set(f, "pages_before", 0, "body", 0, "commit_id", value="short"), "invalid review commit"),
    ("review_missing_sha", lambda f: f["pages_before"][0]["body"][0].pop("commit_id"), "invalid review commit"),
    ("review_ts_missing", lambda f: f["pages_before"][0]["body"][0].pop("submitted_at"), "invalid UTC review"),
    ("review_ts_offset", lambda f: _set(f, "pages_before", 0, "body", 0, "submitted_at", value="2026-11-23T09:10:00+09:00"), "invalid UTC review"),
    ("review_ts_impossible", lambda f: _set(f, "pages_before", 0, "body", 0, "submitted_at", value="2026-02-30T00:00:00Z"), "invalid UTC review"),
    ("review_user_missing", lambda f: f["pages_before"][0]["body"][0].pop("user"), "invalid GitHub reviewer"),
    ("review_user_bool", lambda f: _set(f, "pages_before", 0, "body", 0, "user", "id", value=True), "invalid GitHub reviewer"),
    ("review_user_bot", lambda f: _set(f, "pages_before", 0, "body", 0, "user", "type", value="Bot"), "invalid GitHub reviewer"),
    ("review_user_bad_login", lambda f: _set(f, "pages_before", 0, "body", 0, "user", "login", value="../../escape"), "invalid GitHub reviewer"),
    ("review_page_bad_url", lambda f: _set(f, "pages_before", 0, "request_url", value="http://api.github.com"), "unexpected PR-review host/path"),
    ("review_page_external", lambda f: _set(f, "pages_before", 0, "request_url", value=url(1).replace("api.github.com", "fake.example")), "unexpected PR-review host/path"),
    ("review_page_wrong_pr", lambda f: _set(f, "pages_before", 0, "request_url", value=url(1).replace("/pulls/42/", "/pulls/43/")), "unexpected PR-review host/path"),
    ("review_page_wrong_page", lambda f: _set(f, "pages_before", 0, "request_url", value=url(2)), "PR-review page failed"),
    ("review_page_duplicate_param", lambda f: _set(f, "pages_before", 0, "request_url", value=url(1)+"&page=1"), "ambiguous PR-review"),
    ("review_page_extra_query", lambda f: _set(f, "pages_before", 0, "request_url", value=url(1)+"&token=dummy"), "ambiguous PR-review"),
    ("review_page_per_page", lambda f: _set(f, "pages_before", 0, "request_url", value=url(1).replace("per_page=100","per_page=20")), "invalid PR-review page size/number"),
    ("review_page_01", lambda f: _set(f, "pages_before", 0, "request_url", value=url("01")), "invalid PR-review page size/number"),
    ("review_page_status_403", lambda f: _set(f, "pages_before", 0, "status_code", value=403), "PR-review page failed"),
    ("review_page_status_true", lambda f: _set(f, "pages_before", 0, "status_code", value=True), "PR-review page failed"),
    ("review_page_body_not_array", lambda f: _set(f, "pages_before", 0, "body", value={"wrong":1}), "invalid PR-review body"),
    ("review_page_bad_headers", lambda f: _set(f, "pages_before", 0, "headers", value=[]), "missing PR-review Link"),
    ("review_page_unexpected_next", lambda f: _set(f, "pages_before", 0, "headers", "Link", value=f'<{url(2)}>; rel="next"'), "unfetched PR-review continuation"),
    ("review_page_bad_link", lambda f: _set(f, "pages_before", 0, "headers", "Link", value=f'<{url(2)}>; rel=next'), "malformed PR-review Link"),
    ("review_page_dup_link", lambda f: _set(f, "pages_before", 0, "headers", "Link", value=f'<{url(2)}>; rel="next", <{url(2)}>; rel="next"'), "duplicate PR-review Link"),
    ("review_page_fake_last", lambda f: _set(f, "pages_before", 0, "headers", "Link", value=f'<{url(2)}>; rel="last"'), "unfetched PR-review last"),
    ("review_page_fake_first", lambda f: _set(f, "pages_before", 0, "headers", "Link", value=f'<{url(2)}>; rel="first"'), "invalid PR-review Link"),
    ("review_page_bool_number", lambda f: _set(f, "pr_number", value=True), "invalid PR number"),
    ("review_page_zero_number", lambda f: _set(f, "pr_number", value=0), "invalid PR number"),
    ("review_page_no_pages", lambda f: _set(f, "pages_before", value=[]), "missing or excessive PR-review"),
    ("review_page_not_pages", lambda f: _set(f, "pages_before", value={}), "missing or excessive PR-review"),
    ("review_page_11_pages", lambda f: _set(f, "pages_before", value=copy.deepcopy(f["pages_before"])*11), "missing or excessive PR-review"),
    ("review_window_zero", lambda f: _set(f, "finished_at_utc", value=NOW), "invalid PR-review observation window"),
    ("review_window_reversed", lambda f: _set(f, "finished_at_utc", value=NOW-timedelta(seconds=1)), "invalid PR-review observation window"),
    ("review_window_long", lambda f: _set(f, "finished_at_utc", value=NOW+timedelta(seconds=121)), "invalid PR-review observation window"),
    ("review_window_naive", lambda f: _set(f, "started_at_utc", value=NOW.replace(tzinfo=None)), "invalid PR-review observation window"),
    ("review_head_not_sha", lambda f: _set(f, "head_sha", value="oops"), "invalid review target HEAD"),
    ("review_required_zero", lambda f: _set(f, "required_approvals", value=0), "invalid independent approval count"),
    ("review_required_four", lambda f: _set(f, "required_approvals", value=4), "invalid independent approval count"),
    ("review_required_bool", lambda f: _set(f, "required_approvals", value=True), "invalid independent approval count"),
    ("review_author_bot", lambda f: _set(f, "author", "type", value="Bot"), "invalid GitHub reviewer"),
    ("review_pusher_bad", lambda f: _set(f, "last_pusher", "id", value=None), "invalid GitHub reviewer"),
    ("review_push_after_started", lambda f: _set(f, "last_push_at_utc", value="2026-11-23T00:16:00Z"), "last push occurs after"),
    ("review_push_bad_time", lambda f: _set(f, "last_push_at_utc", value="yesterday"), "invalid UTC review"),
    ("review_roster_empty", lambda f: _set(f, "allowed_reviewers", value={}), "missing independent reviewer roster"),
    ("review_roster_bad_key", lambda f: _set(f, "allowed_reviewers", value={"0222":copy.deepcopy(REVIEWER)}), "malformed roster user"),
    ("review_roster_bad_role", lambda f: _set(f, "allowed_reviewers", "222", "permission", value="read"), "roster ID or role"),
    ("review_roster_bad_id", lambda f: _set(f, "allowed_reviewers", "222", "id", value=223), "roster ID or role"),
    ("review_roster_wrong_login", lambda f: _set(f, "allowed_reviewers", "222", "login", value="someone-else"), "no sufficient current"),
    ("review_roster_bot", lambda f: _set(f, "allowed_reviewers", "222", "type", value="Bot"), "invalid GitHub reviewer"),
    ("review_head_differs", lambda f: _set(f, "head_sha", value=OLD), "stale approval"),
    ("review_approval_dismissed", lambda f: _set(f, "pages_before", 0, "body", 0, "state", value="DISMISSED"), "PR review history changed"),
    ("review_approval_changed_requested", lambda f: _set(f, "pages_before", 0, "body", 0, "state", value="CHANGES_REQUESTED"), "PR review history changed"),
    ("review_stale_base_not_relevant", lambda f: _set(f, "pages_after", 0, "body", 0, "commit_id", value=OLD), "PR review history changed"),
]
for label, mutate, fragment in CASES:
    def make_test(mutator=mutate, expected=fragment):
        def test(self):
            self.f = fixture()
            mutator(self.f)
            self.deny(expected)
        return test
    setattr(ReviewEvidenceTests, "test_table_" + label, make_test())


if __name__ == "__main__":
    unittest.main()
