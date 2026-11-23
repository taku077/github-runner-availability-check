"""SEC157: simulated fixed-scope GitHub tool-dispatch policy.

Security goal: demonstrate that an old registry next or handoff text
cannot authorize a request to paused private CI via this MOCK broker.
No GitHub network, real credentials, model input interception, native plugin
hook or live execution-path enforcement exists.

This code is PR-authored and PR-controlled: a model can still call native
tools without passing this broker. A test pass proves no production protection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

PRIVATE_REPO = "taku077/pcfm-forensic-dev"
PUBLIC_REPO = "taku077/github-runner-availability-check"
PRIVATE_SAFE_DOCS = frozenset((
    "docs/HANDOFF_CURRENT.md",
    "docs/PCFM_RCA_ACTIVE_HANDOFF_20261112.md",
    "docs/ARTIFACT_REGISTRY.json",
))
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_TOOL_PREFIX = "mcp__GitHub__"
_SIMULATED_SAFE_READS = frozenset((
    "fetch_file", "get_pr_info", "fetch_workflow_run_jobs",
    "fetch_workflow_job_logs", "fetch_commit_workflow_runs",
))
_ALLOWED_PARAMS = {
    "fetch_file": frozenset(("repository_full_name", "path", "ref")),
    "get_pr_info": frozenset(("repository_full_name", "pr_number")),
    "fetch_workflow_run_jobs": frozenset(("repo_full_name", "run_id")),
    "fetch_workflow_job_logs": frozenset(("repo_full_name", "job_id")),
    "fetch_commit_workflow_runs": frozenset(("repo_full_name", "commit_sha")),
}


@dataclass(frozen=True)
class ScopedDecision:
    """No authorization assertions even for safe-shaped read-only calls."""
    status: str
    reason: str
    tool: str | None

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "tool": self.tool,
            "native_tool_intercepted": False,
            "caller_identity_verified": False,
            "external_policy_verified": False,
            "owner_exception_verified": False,
            "production_enforcement": False,
            "private_ci_reopened": False,
            "real_tool_dispatched": False,
        }


def _allowed_params(tool: str, params: dict) -> bool:
    keys = set(params)
    if tool == "fetch_file":
        return keys in (
            {"repository_full_name", "path"},
            {"repository_full_name", "path", "ref"})
    return keys == _ALLOWED_PARAMS[tool]


def _valid_ref(ref: Any) -> bool:
    return type(ref) is str and (_SHA40.fullmatch(ref) is not None or
                                 ref == "main")


def simulate_policy(*, tool_name: Any, parameters: Any,
                    source_label: Any = "untrusted_handoff",
                    owner_override_claim: Any = None) -> ScopedDecision:
    """Deny by default based on typed tool arguments, never old prose.

    source_label and owner_override_claim are untrusted annotations and have
    no effect. Even a claimed direct user approval cannot unpause private CI:
    independent authorization is not implemented in this prototype.
    """
    if (type(tool_name) is not str or
            not tool_name.startswith(_TOOL_PREFIX)):
        return ScopedDecision("SIMULATED_DENY", "UNKNOWN_TOOL", None)
    tool = tool_name[len(_TOOL_PREFIX):]
    if (tool not in _SIMULATED_SAFE_READS or
            type(parameters) is not dict):
        return ScopedDecision("SIMULATED_DENY", "UNSUPPORTED_ACTION", tool)
    if (not all(type(k) is str for k in parameters) or
            not _allowed_params(tool, parameters)):
        return ScopedDecision("SIMULATED_DENY", "ARGUMENT_SHAPE_INVALID", tool)

    repo_key = ("repository_full_name" if tool in ("fetch_file", "get_pr_info")
                else "repo_full_name")
    repo = parameters.get(repo_key)
    if type(repo) is not str or repo not in (PRIVATE_REPO, PUBLIC_REPO):
        return ScopedDecision("SIMULATED_DENY", "REPO_NOT_IN_ALLOWED_SET", tool)

    # Stop decision is a fixed test-policy constant, not inferred from
    # registry next, stale HANDOFF notes or assistant output.
    if repo == PRIVATE_REPO:
        if tool != "fetch_file":
            return ScopedDecision(
                "SIMULATED_DENY", "PAUSED_PRIVATE_CI_AND_NON_DOC_TOOL", tool)
        private_path = parameters.get("path")
        if (type(private_path) is not str or
                private_path not in PRIVATE_SAFE_DOCS or
                ("ref" in parameters and
                 not _valid_ref(parameters["ref"]))):
            return ScopedDecision(
                "SIMULATED_DENY", "PRIVATE_DOC_PATH_NOT_ALLOWED", tool)
        return ScopedDecision(
            "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION",
            "PRIVATE_HANDOFF_DOC_READ_ONLY", tool)

    if tool == "fetch_file":
        path = parameters.get("path")
        if (type(path) is not str or not (
                path.startswith("security/sec142/") or
                path.startswith("docs/SEC15")) or
                ".." in path.split("/") or
                not path.endswith((".py", ".md", ".json")) or
                ("ref" in parameters and
                 not _valid_ref(parameters["ref"]))):
            return ScopedDecision(
                "SIMULATED_DENY", "PUBLIC_FILE_OUTSIDE_TEST_SCOPE", tool)
    elif tool == "get_pr_info":
        number = parameters.get("pr_number")
        if type(number) is not int or number not in (2, 3, 4):
            return ScopedDecision(
                "SIMULATED_DENY", "PUBLIC_PR_OUTSIDE_TEST_SCOPE", tool)
    elif tool == "fetch_commit_workflow_runs":
        if (not _valid_ref(parameters.get("commit_sha")) or
                parameters["commit_sha"] == "main"):
            return ScopedDecision(
                "SIMULATED_DENY", "PUBLIC_COMMIT_SHA_UNPINNED", tool)
    else:
        id_key = "run_id" if tool == "fetch_workflow_run_jobs" else "job_id"
        value = parameters.get(id_key)
        if type(value) is not int or not 0 < value < (1 << 63):
            return ScopedDecision(
                "SIMULATED_DENY", "PUBLIC_RUN_OR_JOB_ID_INVALID", tool)

    return ScopedDecision(
        "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION",
        "PUBLIC_CI_READ_SHAPE_ONLY", tool)


class SimulatedDispatch:
    """Local fake-handler adapter, never wired as native tool intercept.

    Handler is always a recorder in tests, not a network client.
    """
    def __init__(self, handler: Callable[[str, dict], Any]):
        if not callable(handler):
            raise TypeError("test handler must be callable")
        self._handler = handler
        self.calls = 0

    def dispatch(self, *, tool_name: Any, parameters: Any,
                 source_label: Any = None,
                 owner_override_claim: Any = None) -> tuple[ScopedDecision, Any]:
        decision = simulate_policy(
            tool_name=tool_name, parameters=parameters,
            source_label=source_label,
            owner_override_claim=owner_override_claim)
        if decision.status != "SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION":
            return decision, None
        # This is a mock execution counter, not a real tool dispatch event.
        self.calls += 1
        return decision, self._handler(tool_name, dict(parameters))
