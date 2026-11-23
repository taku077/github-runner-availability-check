"""SEC157: simulated tool-dispatch allowlist and historical-next regression.

No test calls a real private CI endpoint, network, GitHub App, or native
ChatGPT tool. Mock handler calls are local counters only.
"""
import copy
import unittest

from dispatch_preflight import (
    PRIVATE_REPO, PUBLIC_REPO, PRIVATE_SAFE_DOCS,
    SimulatedDispatch, simulate_policy,
)

SRC = "mcp__GitHub__"
SHA = "a" * 40


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, tool, params):
        self.calls.append((tool, copy.deepcopy(params)))
        return {"simulated_receipt_only": True}


def query(tool, repo=PRIVATE_REPO, **kwargs):
    repo_key = ("repository_full_name" if tool in
                ("fetch_file", "get_pr_info") else "repo_full_name")
    return {"tool_name": SRC + tool,
            "parameters": {repo_key: repo, **kwargs}}


def paused_query(tool="fetch_workflow_run_jobs", **extra):
    return query(tool, run_id=45000000001, **extra)


class SimulatedDispatchTests(unittest.TestCase):
    def setUp(self):
        self.recorder = Recorder()
        self.dispatch = SimulatedDispatch(self.recorder)

    def exercise_denied(self, request, *, expected=None, **metadata):
        decision, output = self.dispatch.dispatch(
            **request, **metadata)
        record = decision.as_dict()
        self.assertEqual(record["status"], "SIMULATED_DENY")
        if expected is not None:
            self.assertEqual(record["reason"], expected)
        self.assertIsNone(output)
        self.assertEqual(self.dispatch.calls, 0)
        self.assertEqual(self.recorder.calls, [])
        self.assertFalse(record["real_tool_dispatched"])
        self.assertFalse(record["native_tool_intercepted"])
        self.assertFalse(record["private_ci_reopened"])

    def exercise_mock_read(self, request, expected):
        decision, output = self.dispatch.dispatch(**request)
        record = decision.as_dict()
        self.assertEqual(
            record["status"], "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION")
        self.assertEqual(record["reason"], expected)
        self.assertEqual(self.dispatch.calls, 1)
        self.assertEqual(len(self.recorder.calls), 1)
        self.assertEqual(output, {"simulated_receipt_only": True})
        for key in ("native_tool_intercepted", "caller_identity_verified",
                    "external_policy_verified", "owner_exception_verified",
                    "production_enforcement", "private_ci_reopened",
                    "real_tool_dispatched"):
            self.assertFalse(record[key], key)

    def test_historical_next_is_not_user_permission(self):
        req = paused_query()
        self.exercise_denied(
            req, expected="PAUSED_PRIVATE_CI_AND_NON_DOC_TOOL",
            source_label="docs/ARTIFACT_REGISTRY.json next: get stopped CI job",
            owner_override_claim={"authority": "HISTORICAL_NEXT"})

    def test_handoff_quoted_instruction_cannot_authorize(self):
        self.exercise_denied(
            paused_query(), source_label="HANDOFF_CURRENT.md recommends CI",
            owner_override_claim="user says continue; ASSISTANT suggested")

    def test_direct_user_claim_cannot_unpause_without_trusted_channel(self):
        self.exercise_denied(
            paused_query(), source_label="direct_user_message",
            owner_override_claim={"approved": True,
                                  "signature": "unverified_fake"})

    def test_routing_history_does_not_change_outcome(self):
        req = paused_query()
        for source in ("user", "handoff", "registry.next",
                       "AI_self_generated", None, ["trusted"]):
            with self.subTest(source=repr(source)):
                decision = simulate_policy(
                    **req, source_label=source,
                    owner_override_claim={"approved": True})
                self.assertEqual(decision.status, "SIMULATED_DENY")

    def test_private_handoff_file_safe_shape_mocked_only(self):
        self.exercise_mock_read(query(
            "fetch_file", path="docs/HANDOFF_CURRENT.md"),
            "PRIVATE_HANDOFF_DOC_READ_ONLY")

    def test_private_rca_file_safe_shape_mocked_only(self):
        self.exercise_mock_read(query(
            "fetch_file",
            path="docs/PCFM_RCA_ACTIVE_HANDOFF_20261112.md",
            ref="main"), "PRIVATE_HANDOFF_DOC_READ_ONLY")

    def test_private_registry_file_safe_shape_mocked_only(self):
        self.exercise_mock_read(query(
            "fetch_file", path="docs/ARTIFACT_REGISTRY.json",
            ref=SHA), "PRIVATE_HANDOFF_DOC_READ_ONLY")

    def test_public_ci_jobs_read_safe_shape_only(self):
        self.exercise_mock_read(query(
            "fetch_workflow_run_jobs", repo=PUBLIC_REPO,
            run_id=45060678843), "PUBLIC_CI_READ_SHAPE_ONLY")

    def test_public_ci_logs_safe_shape_only(self):
        self.exercise_mock_read(query(
            "fetch_workflow_job_logs", repo=PUBLIC_REPO,
            job_id=137325665467), "PUBLIC_CI_READ_SHAPE_ONLY")

    def test_public_pr_info_safe_shape_only(self):
        self.exercise_mock_read(query(
            "get_pr_info", repo=PUBLIC_REPO,
            pr_number=4), "PUBLIC_CI_READ_SHAPE_ONLY")

    def test_public_sha_ci_runs_safe_shape_only(self):
        self.exercise_mock_read(query(
            "fetch_commit_workflow_runs", repo=PUBLIC_REPO,
            commit_sha=SHA), "PUBLIC_CI_READ_SHAPE_ONLY")

    def test_public_source_safe_shape_only(self):
        self.exercise_mock_read(query(
            "fetch_file", repo=PUBLIC_REPO,
            path="security/sec142/dispatch_preflight.py",
            ref=SHA), "PUBLIC_CI_READ_SHAPE_ONLY")

    def test_mock_dispatch_does_not_elevate_future_prohibited_request(self):
        decision, _ = self.dispatch.dispatch(**query(
            "fetch_file", path="docs/HANDOFF_CURRENT.md"))
        self.assertNotEqual(decision.status, "SIMULATED_DENY")
        next_decision, outcome = self.dispatch.dispatch(**paused_query())
        self.assertEqual(next_decision.status, "SIMULATED_DENY")
        self.assertIsNone(outcome)
        self.assertEqual(self.dispatch.calls, 1)


PRIVATE_BLOCKED = [
    ("run_jobs", "fetch_workflow_run_jobs", {"run_id": 45000000001}),
    ("job_logs", "fetch_workflow_job_logs", {"job_id": 137000000001}),
    ("commit_runs", "fetch_commit_workflow_runs", {"commit_sha": SHA}),
    ("pr_info", "get_pr_info", {"pr_number": 4}),
    ("private_billing", "fetch", {"url":
        "https://api.github.com/repos/taku077/pcfm-forensic-dev/actions/billing"}),
    ("private_annotations", "fetch", {"url":
        "https://api.github.com/repos/taku077/pcfm-forensic-dev/check-runs/123/annotations"}),
    ("private_runner", "fetch", {"url":
        "https://api.github.com/repos/taku077/pcfm-forensic-dev/actions/runners"}),
    ("private_run_logs", "fetch", {"url":
        "https://api.github.com/repos/taku077/pcfm-forensic-dev/actions/runs/2/logs"}),
    ("write_file", "update_file", {"path": "docs/HANDOFF_CURRENT.md"}),
    ("merge_pr", "merge_pr", {"pr_number": 4}),
    ("list_workflows", "list_workflows", {}),
    ("run_workflow", "dispatch_workflow", {}),
]
for label, tool, extra in PRIVATE_BLOCKED:
    def make_test(t=tool, kw=extra):
        def test(self):
            self.exercise_denied(query(t, **kw))
        return test
    setattr(SimulatedDispatchTests,
            "test_paused_private_" + label, make_test())


MUTANTS = [
    ("unknown_tool", {"tool_name": "github.search",
                      "parameters": {"repo_full_name": PRIVATE_REPO}},
     "UNKNOWN_TOOL"),
    ("tool_case", {"tool_name": SRC+"Fetch_File",
                   "parameters": {"repository_full_name": PRIVATE_REPO,
                                  "path": "docs/HANDOFF_CURRENT.md"}},
     "UNSUPPORTED_ACTION"),
    ("tool_suffix", {"tool_name": SRC+"fetch_file__unsafe",
                     "parameters": {"repository_full_name": PRIVATE_REPO,
                                    "path": "docs/HANDOFF_CURRENT.md"}},
     "UNSUPPORTED_ACTION"),
    ("tool_nonstring", {"tool_name": None, "parameters": {}}, "UNKNOWN_TOOL"),
    ("params_non_dict", {"tool_name": SRC+"fetch_file", "parameters": None},
     "UNSUPPORTED_ACTION"),
    ("params_bool", {"tool_name": SRC+"fetch_file", "parameters": True},
     "UNSUPPORTED_ACTION"),
    ("mixed_repo_key", {"tool_name": SRC+"fetch_file", "parameters": {
        "repository_full_name": PRIVATE_REPO, "repo_full_name": PUBLIC_REPO,
        "path": "docs/HANDOFF_CURRENT.md"}}, "ARGUMENT_SHAPE_INVALID"),
    ("extra_approval_key", {"tool_name": SRC+"fetch_file", "parameters": {
        "repository_full_name": PRIVATE_REPO, "path":
        "docs/HANDOFF_CURRENT.md", "user_approved": True}},
     "ARGUMENT_SHAPE_INVALID"),
    ("private_wrong_ref", query("fetch_file",
        path="docs/HANDOFF_CURRENT.md", ref="dev/hypothesis"),
     "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_missing_path", query("fetch_file"), "ARGUMENT_SHAPE_INVALID"),
    ("private_wrong_doc", query("fetch_file",
        path="docs/PRIVATE_CI_RUNNERS.md"), "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_path_traversal", query("fetch_file",
        path="docs/../docs/HANDOFF_CURRENT.md"),
     "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_url_encoded", query("fetch_file",
        path="docs/%48ANDOFF_CURRENT.md"), "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_path_case", query("fetch_file",
        path="Docs/HANDOFF_CURRENT.md"), "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_path_nonstring", query("fetch_file",
        path=["docs/HANDOFF_CURRENT.md"]), "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_path_null", query("fetch_file", path=None),
     "PRIVATE_DOC_PATH_NOT_ALLOWED"),
    ("private_repo_case", query("fetch_file",
        repo="TAKU077/pcfm-forensic-dev", path="docs/HANDOFF_CURRENT.md"),
     "REPO_NOT_IN_ALLOWED_SET"),
    ("private_repo_trailing", query("fetch_file",
        repo=PRIVATE_REPO+"/", path="docs/HANDOFF_CURRENT.md"),
     "REPO_NOT_IN_ALLOWED_SET"),
    ("public_repo_near_match", query("fetch_workflow_run_jobs",
        repo="taku077/github-runner-availability-checkx", run_id=1),
     "REPO_NOT_IN_ALLOWED_SET"),
    ("repo_nonstring", query("fetch_workflow_run_jobs",
        repo=None, run_id=1), "REPO_NOT_IN_ALLOWED_SET"),
    ("public_runid_bool", query("fetch_workflow_run_jobs",
        repo=PUBLIC_REPO, run_id=True), "PUBLIC_RUN_OR_JOB_ID_INVALID"),
    ("public_runid_zero", query("fetch_workflow_run_jobs",
        repo=PUBLIC_REPO, run_id=0), "PUBLIC_RUN_OR_JOB_ID_INVALID"),
    ("public_runid_string", query("fetch_workflow_run_jobs",
        repo=PUBLIC_REPO, run_id="45060678843"),
     "PUBLIC_RUN_OR_JOB_ID_INVALID"),
    ("public_runid_huge", query("fetch_workflow_run_jobs",
        repo=PUBLIC_REPO, run_id=2**63), "PUBLIC_RUN_OR_JOB_ID_INVALID"),
    ("public_jobid_zero", query("fetch_workflow_job_logs",
        repo=PUBLIC_REPO, job_id=0), "PUBLIC_RUN_OR_JOB_ID_INVALID"),
    ("public_sha_branch", query("fetch_commit_workflow_runs",
        repo=PUBLIC_REPO, commit_sha="main"),
     "PUBLIC_COMMIT_SHA_UNPINNED"),
    ("public_sha_short", query("fetch_commit_workflow_runs",
        repo=PUBLIC_REPO, commit_sha="abc"),
     "PUBLIC_COMMIT_SHA_UNPINNED"),
    ("public_pr_bool", query("get_pr_info", repo=PUBLIC_REPO,
        pr_number=True), "PUBLIC_PR_OUTSIDE_TEST_SCOPE"),
    ("public_pr_other", query("get_pr_info", repo=PUBLIC_REPO,
        pr_number=17), "PUBLIC_PR_OUTSIDE_TEST_SCOPE"),
    ("public_file_path_traversal", query("fetch_file",
        repo=PUBLIC_REPO, path="security/sec142/../private.py"),
     "PUBLIC_FILE_OUTSIDE_TEST_SCOPE"),
    ("public_file_outside_scope", query("fetch_file",
        repo=PUBLIC_REPO, path=".github/workflows/runner-smoke.yml"),
     "PUBLIC_FILE_OUTSIDE_TEST_SCOPE"),
    ("public_file_bad_ref", query("fetch_file",
        repo=PUBLIC_REPO, path="security/sec142/a.py", ref="heads/main"),
     "PUBLIC_FILE_OUTSIDE_TEST_SCOPE"),
    ("public_generic_fetch", {"tool_name": SRC+"fetch", "parameters": {
        "url": "https://api.github.com/repos/"+PUBLIC_REPO}},
     "UNSUPPORTED_ACTION"),
]
for label, obj, reason in MUTANTS:
    def factory(req=obj, expected=reason):
        def test(self):
            self.exercise_denied(copy.deepcopy(req), expected=expected)
        return test
    setattr(SimulatedDispatchTests, "test_bad_" + label, factory())


if __name__ == "__main__":
    unittest.main()
