"""SEC149 offline page-chain negative fixtures; NO live credentials or network."""
import copy
import unittest

from check_page_chain import (
    _page_from_url, compare_paginated_check_readback,
    flatten_check_run_pages)
from test_provider_readback import fixture, HEAD, REPO
from trusted_check_policy import Rejected

def url(n, head=HEAD, *, host="api.github.com", filt="all"):
    return (f"https://{host}/repos/{REPO}/commits/{head}/check-runs"
            f"?per_page=100&filter={filt}&page={n}")

def make_pages(size):
    base = fixture()["check_run_by_id"]
    runs = [copy.deepcopy(base)]
    for n in range(2, size+1):
        item = copy.deepcopy(base)
        item["id"] = 11223344 + n
        item["name"] = "unrelated-check"
        item["external_id"] = "unrelated" + str(n)
        runs.append(item)
    pages = []
    count = (size+99)//100
    for index in range(1, count+1):
        sl = runs[(index-1)*100:index*100]
        next_link = (f'<{url(index+1)}>; rel="next", '
                     f'<{url(count)}>; rel="last"'
                     if index < count else "")
        pages.append({"request_url": url(index), "status_code": 200,
                      "headers": {"Link": next_link},
                      "body": {"total_count": size,
                               "check_runs": sl}})
    return pages

class CheckPageChainTests(unittest.TestCase):
    def denied(self, pages, text):
        with self.assertRaisesRegex(Rejected, text):
            flatten_check_run_pages(page_responses=pages, head_sha=HEAD)

    def test_single_page_success_is_not_authorization(self):
        args = fixture()
        pages = make_pages(1)
        obj = compare_paginated_check_readback(
            page_responses=pages, local_intent=args["local_intent"],
            live_pr_before=args["live_pr_before"],
            live_pr_after=args["live_pr_after"],
            check_run_by_id=args["check_run_by_id"],
            expected_app_id=args["expected_app_id"])
        self.assertEqual(obj.as_dict()["status"],
                         "SYNTHETIC_MATCH_UNTRUSTED_NOT_AUTHORIZED")
        self.assertFalse(obj.as_dict()["merge_authorized"])
        self.assertFalse(obj.as_dict()["api_authenticated"])

    def test_exactly_100_uses_one_page(self):
        self.assertEqual(flatten_check_run_pages(
            page_responses=make_pages(100), head_sha=HEAD)["total_count"],100)

    def test_101_two_pages_candidate_only(self):
        args=fixture()
        obj=compare_paginated_check_readback(
            page_responses=make_pages(101), local_intent=args["local_intent"],
            live_pr_before=args["live_pr_before"],
            live_pr_after=args["live_pr_after"],
            check_run_by_id=args["check_run_by_id"],
            expected_app_id=args["expected_app_id"])
        self.assertFalse(obj.as_dict()["merge_authorized"])

    def test_three_pages_success(self):
        self.assertEqual(len(flatten_check_run_pages(
            page_responses=make_pages(205),
            head_sha=HEAD)["check_runs"]),205)

    def test_no_pages(self):
        self.denied([], "missing or excessive")

    def test_first_page_missing(self):
        self.denied(make_pages(205)[1:], "reordered")

    def test_last_page_missing(self):
        self.denied(make_pages(205)[:2], "incomplete API page set")

    def test_duplicate_page(self):
        pages=make_pages(101)
        pages[1]=copy.deepcopy(pages[0])
        self.denied(pages, "reordered")

    def test_wrong_head_ref(self):
        pages=make_pages(1)
        pages[0]["request_url"]=url(1, head="c"*40)
        self.denied(pages,"untrusted API URL")

    def test_untrusted_host(self):
        pages=make_pages(1)
        pages[0]["request_url"]=url(1, host="evil.example")
        self.denied(pages,"untrusted API URL")

    def test_filter_latest_disallowed(self):
        pages=make_pages(1)
        pages[0]["request_url"]=url(1, filt="latest")
        self.denied(pages, "API filtering")

    def test_duplicate_query_parameter(self):
        pages=make_pages(1)
        pages[0]["request_url"]+="&page=1"
        self.denied(pages, "duplicate API query")

    def test_query_noncanonical_page(self):
        pages=make_pages(1)
        pages[0]["request_url"]=url("01")
        self.denied(pages, "invalid API page number")

    def test_wrong_page_size(self):
        pages=make_pages(1)
        pages[0]["request_url"]=url(1).replace("per_page=100","per_page=10")
        self.denied(pages,"API filtering")

    def test_status_403(self):
        pages=make_pages(1)
        pages[0]["status_code"]=403
        self.denied(pages,"non-success")

    def test_status_boolean_not_200(self):
        pages=make_pages(1)
        pages[0]["status_code"]=True
        self.denied(pages,"non-success")

    def test_count_changes_on_page2(self):
        pages=make_pages(101)
        pages[1]["body"]["total_count"]=102
        self.denied(pages,"total_count changed")

    def test_non_full_page_before_last(self):
        pages=make_pages(101)
        pages[0]["body"]["check_runs"].pop()
        self.denied(pages,"partial, missing")

    def test_link_missing_on_first_page(self):
        pages=make_pages(101)
        pages[0]["headers"]={}
        self.denied(pages,"missing or incorrect next")

    def test_link_points_to_wrong_page(self):
        pages=make_pages(101)
        pages[0]["headers"]["Link"]=f'<{url(3)}>; rel="next"'
        self.denied(pages,"missing or incorrect next")

    def test_link_untrusted_host_rejected(self):
        pages=make_pages(101)
        pages[0]["headers"]["Link"]=f'<{url(2,host="evil.example")}>; rel="next"'
        self.denied(pages,"untrusted API URL")

    def test_extra_next_on_last(self):
        pages=make_pages(1)
        pages[0]["headers"]["Link"]=f'<{url(2)}>; rel="next"'
        self.denied(pages,"unexpected next")

    def test_inconsistent_last(self):
        pages=make_pages(205)
        pages[0]["headers"]["Link"] = (
            f'<{url(2)}>; rel="next", <{url(2)}>; rel="last"')
        self.denied(pages,"inconsistent pagination")

    def test_duplicate_rel(self):
        pages=make_pages(101)
        pages[0]["headers"]["Link"] = (
            f'<{url(2)}>; rel="next", <{url(2)}>; rel="next"')
        self.denied(pages,"duplicate pagination")

    def test_malformed_link(self):
        pages=make_pages(101)
        pages[0]["headers"]["Link"] = f'<{url(2)}>; rel=next'
        self.denied(pages,"malformed Link")

    def test_over_1000_denied(self):
        pages=make_pages(1001)
        self.denied(pages,"excessive|invalid API total_count")

    def test_extra_page_denied(self):
        pages=make_pages(1)
        pages.append(copy.deepcopy(pages[0]))
        pages[1]["request_url"]=url(2)
        self.denied(pages,"excess page")

    def test_duplicate_check_id_rejected_by_sec147(self):
        args=fixture()
        pages=make_pages(101)
        pages[1]["body"]["check_runs"][0]["id"]=11223344
        with self.assertRaisesRegex(Rejected,"duplicate or invalid check run"):
            compare_paginated_check_readback(
                page_responses=pages, local_intent=args["local_intent"],
                live_pr_before=args["live_pr_before"],
                live_pr_after=args["live_pr_after"],
                check_run_by_id=args["check_run_by_id"],
                expected_app_id=args["expected_app_id"])

    def test_draft_pr_not_accepted(self):
        args=fixture()
        args["live_pr_before"]["draft"]=True
        args["live_pr_after"]["draft"]=True
        with self.assertRaisesRegex(Rejected,"unexpected PR identity"):
            compare_paginated_check_readback(
                page_responses=make_pages(1),local_intent=args["local_intent"],
                live_pr_before=args["live_pr_before"],
                live_pr_after=args["live_pr_after"],
                check_run_by_id=args["check_run_by_id"],
                expected_app_id=args["expected_app_id"])

if __name__ == "__main__":
    unittest.main()
