"""SEC147: strict, SOURCE-ONLY GitHub Check Run readback comparison.

This code does not call GitHub. All JSON-like inputs (including 'App ID') are
UNTRUSTED until fetched by an independent authenticated GitHub App host.
Even a perfect synthetic match cannot authorize a merge or emit a check run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from trusted_check_policy import Rejected

REPOSITORY = "taku077/github-runner-availability-check"
REQUIRED_FUTURE_CHECK = "pcfm-independent-admission"
CURRENT_UNTRUSTED_ACTIONS_APP = 15368
SHA40 = re.compile(r"^[0-9a-f]{40}$")
INTENT64 = re.compile(r"^[0-9a-f]{64}$")


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _sha(value: Any) -> bool:
    return type(value) is str and SHA40.fullmatch(value) is not None


def _identity(record: dict) -> tuple:
    """Canonical fields that must agree between check-run list and get."""
    try:
        return (record["id"], record["name"], record["head_sha"],
                record["external_id"], record["app"]["id"],
                record["status"], record["conclusion"])
    except (KeyError, TypeError, AttributeError) as exc:
        raise Rejected("check run readback is incomplete") from exc


def _pr_identity(record: dict) -> tuple:
    try:
        return (record["number"], record["head"]["sha"],
                record["base"]["ref"],
                record["base"]["repo"]["full_name"],
                record["state"], record["draft"])
    except (KeyError, TypeError, AttributeError) as exc:
        raise Rejected("PR readback is incomplete") from exc


@dataclass(frozen=True)
class Readback:
    observed_check_id: int
    intent_id: str
    head_sha: str
    app_id: int
    disposition: str = "SYNTHETIC_MATCH_UNTRUSTED_NOT_AUTHORIZED"

    def as_dict(self):
        return {
            "check_id": self.observed_check_id,
            "intent_id": self.intent_id,
            "head_sha": self.head_sha,
            "app_id": self.app_id,
            "status": self.disposition,
            "check_written": False,
            "merge_authorized": False,
            "api_authenticated": False,
            "independent_operator_attested": False,
            "ruleset_enforcement_verified": False,
        }


def compare_check_readback(*, local_intent: dict, live_pr_before: dict,
                           live_pr_after: dict, check_run_by_id: dict,
                           check_run_list: dict, expected_app_id: int,
                           repository: str = REPOSITORY) -> Readback:
    """Reject inconsistent API-shaped input; never grant a PASS.

    The trusted host must independently derive expected_app_id from signed
    installation/configuration; a caller-provided ID is NOT an attestation.
    'check_run_list' must include all pages, and the host must independently
    prove completeness. This function checks only declared page counts.
    The PR read-before/read-after comparison is NOT an atomic snapshot.
    """
    if repository != REPOSITORY:
        raise Rejected("unexpected repository")
    if (not _positive(expected_app_id) or
            expected_app_id == CURRENT_UNTRUSTED_ACTIONS_APP):
        raise Rejected("untrusted or invalid expected App source")
    if not isinstance(local_intent, dict):
        raise Rejected("invalid local outbox intent")
    intent_id = local_intent.get("intent_id")
    head = local_intent.get("head_sha")
    if (type(intent_id) is not str or
            INTENT64.fullmatch(intent_id) is None or not _sha(head)):
        raise Rejected("invalid outbox intent ID or head")
    if local_intent.get("status") not in (
            "UNKNOWN_REMOTE_RESULT", "RECONCILIATION_HOLD"):
        raise Rejected("local outbox has no uncertain remote result")
    if local_intent.get("check_written") is not False:
        raise Rejected("local state already claims a check write")
    before = _pr_identity(live_pr_before)
    after = _pr_identity(live_pr_after)
    if before != after:
        raise Rejected("PR changed during provider readback")
    number, pr_head, base_ref, base_repo, state, draft = before
    if (not _positive(number) or pr_head != head or
            base_ref != "main" or base_repo != repository or
            state != "open" or draft is not False):
        raise Rejected("unexpected PR identity/head/base/state")
    if not isinstance(check_run_by_id, dict):
        raise Rejected("invalid check run detail")
    selected = _identity(check_run_by_id)
    run_id, run_name, run_head, external_id, run_app, status, conclusion = selected
    if (not _positive(run_id) or run_name != REQUIRED_FUTURE_CHECK or
            run_head != head or external_id != intent_id or
            type(run_app) is not int or run_app != expected_app_id or
            status != "completed" or conclusion != "success"):
        raise Rejected("check run head/source/intent/conclusion mismatch")
    if not isinstance(check_run_list, dict):
        raise Rejected("invalid run list")
    total = check_run_list.get("total_count")
    runs = check_run_list.get("check_runs")
    if (type(total) is not int or total <= 0 or
            not isinstance(runs, list) or len(runs) != total or
            total > 1000):
        raise Rejected("incomplete or ambiguous check run pagination")
    seen_ids = set()
    matching = []
    for record in runs:
        if not isinstance(record, dict):
            raise Rejected("malformed check run in list")
        item = _identity(record)
        if not _positive(item[0]) or item[0] in seen_ids:
            raise Rejected("duplicate or invalid check run ID")
        seen_ids.add(item[0])
        if (item[1], item[2], item[3], item[4]) == (
                REQUIRED_FUTURE_CHECK, head, intent_id, expected_app_id):
            matching.append(item)
    if len(matching) != 1:
        raise Rejected("zero or ambiguous matching App check run")
    if matching[0] != selected:
        raise Rejected("list and detail check run disagree")
    return Readback(run_id, intent_id, head, expected_app_id)
