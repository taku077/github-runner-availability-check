"""SEC158: verify mock preflight has no callable execution path or receipts.

These are PR-controlled synthetic tests, NOT interception/coverage of native
ChatGPT/connector tools. No network or private CI endpoints are executed.
"""
import ast
import inspect
from pathlib import Path
import unittest

import dispatch_preflight
from dispatch_preflight import (
    PUBLIC_REPO, PRIVATE_REPO, SimulatedDispatch, simulate_policy,
)

PREFIX = "mcp__GitHub__"


def request(tool, repo=PUBLIC_REPO, **params):
    key = ("repository_full_name" if tool in ("fetch_file", "get_pr_info")
           else "repo_full_name")
    return {"tool_name": PREFIX + tool,
            "parameters": {key: repo, **params}}


class Tripwire:
    def __init__(self):
        self.calls = 0

    def __call__(self, *a, **kw):
        self.calls += 1
        raise AssertionError("arbitrary callable MUST NOT execute")


class PureInspectorTests(unittest.TestCase):
    def setUp(self):
        self.inspector = SimulatedDispatch()

    def check_no_effect(self, request_args, expected):
        d, response = self.inspector.dispatch(**request_args)
        self.assertEqual(d.status, expected)
        self.assertIsNone(response)
        for key in ("native_tool_intercepted", "caller_identity_verified",
                    "external_policy_verified", "owner_exception_verified",
                    "production_enforcement", "private_ci_reopened",
                    "real_tool_dispatched"):
            self.assertFalse(d.as_dict()[key], key)
        return d

    def test_no_accepted_handler_parameter(self):
        trap = Tripwire()
        with self.assertRaises(TypeError):
            SimulatedDispatch(trap)
        self.assertEqual(trap.calls, 0)

    def test_no_keyword_handler_parameter(self):
        trap = Tripwire()
        with self.assertRaises(TypeError):
            SimulatedDispatch(handler=trap)
        self.assertEqual(trap.calls, 0)

    def test_no_dynamic_hook_assignment(self):
        trap = Tripwire()
        with self.assertRaises(AttributeError):
            self.inspector._handler = trap
        with self.assertRaises(AttributeError):
            self.inspector.execute = trap
        self.assertEqual(trap.calls, 0)

    def test_mock_never_has_credentials_or_handler(self):
        self.assertFalse(hasattr(self.inspector, "__dict__"))
        self.assertFalse(hasattr(self.inspector, "_handler"))
        self.assertFalse(hasattr(self.inspector, "tools"))
        self.assertFalse(hasattr(self.inspector, "session"))

    def test_inspector_only_invokes_policy_function(self):
        """Narrow accidental-regression tripwire, not independent security."""
        tree = ast.parse(inspect.getsource(dispatch_preflight))
        cls = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef) and
                   node.name == "SimulatedDispatch")
        calls = [n for n in ast.walk(cls) if isinstance(n, ast.Call)]
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(calls[0].func, ast.Name)
        self.assertEqual(calls[0].func.id, "simulate_policy")

    def test_allowed_public_shape_does_not_invoke_any_handler(self):
        self.check_no_effect(request(
            "fetch_workflow_run_jobs", run_id=45131334755),
            "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION")
        self.assertEqual(self.inspector.evaluations, 1)
        self.assertEqual(self.inspector.matched_shapes, 1)
        self.assertEqual(self.inspector.denied_shapes, 0)

    def test_allowed_private_handoff_shape_still_does_not_read(self):
        self.check_no_effect(request(
            "fetch_file", repo=PRIVATE_REPO,
            path="docs/HANDOFF_CURRENT.md"),
            "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION")

    def test_stopped_private_ci_read_fails_without_invoking(self):
        self.check_no_effect(request(
            "fetch_workflow_run_jobs", repo=PRIVATE_REPO,
            run_id=45131334755), "SIMULATED_DENY")
        self.assertEqual(self.inspector.matched_shapes, 0)
        self.assertEqual(self.inspector.denied_shapes, 1)

    def test_override_claim_callback_not_executed(self):
        trap = Tripwire()
        args = request("fetch_workflow_run_jobs", repo=PRIVATE_REPO,
                       run_id=1)
        args["source_label"] = trap
        args["owner_override_claim"] = trap
        self.check_no_effect(args, "SIMULATED_DENY")
        self.assertEqual(trap.calls, 0)

    def test_malicious_parameters_object_never_iterated(self):
        class EvilDict(dict):
            def __iter__(self):
                raise AssertionError("never iterate attacker dict subclass")
        self.check_no_effect({
            "tool_name": PREFIX + "fetch_file",
            "parameters": EvilDict(path="docs/HANDOFF_CURRENT.md",
                                   repository_full_name=PRIVATE_REPO),
        }, "SIMULATED_DENY")

    def test_prior_allowed_shape_does_not_carry_authority(self):
        self.check_no_effect(request(
            "fetch_file", repo=PRIVATE_REPO,
            path="docs/ARTIFACT_REGISTRY.json"),
            "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION")
        self.check_no_effect(request(
            "fetch_workflow_job_logs", repo=PRIVATE_REPO,
            job_id=7), "SIMULATED_DENY")
        self.assertEqual(self.inspector.evaluations, 2)
        self.assertEqual(self.inspector.matched_shapes, 1)
        self.assertEqual(self.inspector.denied_shapes, 1)

    def test_decision_does_not_expose_approval_proof(self):
        d, _ = self.inspector.dispatch(**request(
            "get_pr_info", pr_number=4))
        self.assertNotIn("operator_approval", d.as_dict())
        self.assertFalse(d.as_dict()["external_policy_verified"])
        self.assertFalse(d.as_dict()["production_enforcement"])

    def test_no_internal_source_document_storage(self):
        huge_label = "stale-registry-next" * 100
        args = request("fetch_workflow_run_jobs", repo=PRIVATE_REPO, run_id=3)
        args["source_label"] = huge_label
        self.check_no_effect(args, "SIMULATED_DENY")
        self.assertNotIn(huge_label, str(self.inspector))
        self.assertFalse(hasattr(self.inspector, "history"))

    def test_result_never_contains_native_tool_handle(self):
        decision, result = self.inspector.dispatch(**request(
            "fetch_file", repo=PUBLIC_REPO,
            path="security/sec142/dispatch_preflight.py",
            ref="a" * 40))
        self.assertIsNone(result)
        self.assertFalse(decision.as_dict()["real_tool_dispatched"])


DENY_ALIASES = [
    ("private_run_job", "fetch_workflow_run_jobs", {"run_id": 1}),
    ("private_run_log", "fetch_workflow_job_logs", {"job_id": 1}),
    ("private_run_list", "fetch_commit_workflow_runs",
     {"commit_sha": "a"*40}),
    ("private_review", "get_pr_info", {"pr_number": 4}),
    ("unknown_private_action", "fetch_all", {"run_id": 1}),
    ("private_artifact", "download_artifact", {"run_id": 1}),
    ("private_ci_restart", "rerun_workflow", {"run_id": 1}),
    ("private_run_cancel", "cancel_workflow_run", {"run_id": 1}),
    ("private_runner_inventory", "list_self_hosted_runners", {"run_id": 1}),
    ("private_status", "list_check_runs_for_ref", {"ref": "a"*40}),
]
for name, action, kwargs in DENY_ALIASES:
    def generate(a=action, k=kwargs):
        def test(self):
            self.check_no_effect(
                request(a, repo=PRIVATE_REPO, **k), "SIMULATED_DENY")
        return test
    setattr(PureInspectorTests, "test_alias_" + name, generate())


if __name__ == "__main__":
    unittest.main()
