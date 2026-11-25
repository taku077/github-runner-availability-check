"""SEC151: synthetic read-before/read-after race and provenance consistency.

Composition of SEC147-150 *untrusted* comparators. No HTTP, JWT, tokens,
installation, check publication or PR merge. Equality of caller-provided
receipts cannot prove the source/identity/authority of any GitHub response.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from check_page_chain import compare_paginated_check_readback
from installation_scope import (
    REPOSITORY, REPO_ID, inspect_installation_scope,
)
from provider_readback import SHA40
from trusted_check_policy import Rejected

MAX_WINDOW_SECONDS = 120


def _sha(value: Any) -> bool:
    return type(value) is str and SHA40.fullmatch(value) is not None


def _canonical(receipts: Any) -> str:
    """Full deterministic state comparison; no credential material allowed.

    SEC150 already rejects sensitive keys before calling this helper.
    Fail closed for non-JSON or non-finite numeric values.
    """
    try:
        return json.dumps(receipts, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise Rejected("unserializable snapshot data") from exc


def _pr_binding(pr: Any, expected_head: str, expected_base: str,
                expected_pr_number: int) -> tuple:
    if type(pr) is not dict:
        raise Rejected("missing PR snapshot")
    try:
        head = pr["head"]
        base = pr["base"]
        head_repo = head["repo"]
        base_repo = base["repo"]
        data = (pr["number"], head["sha"], head_repo["id"],
                head_repo["full_name"], base["sha"], base["ref"],
                base_repo["id"], base_repo["full_name"], pr["state"],
                pr["draft"], pr["merged"])
    except (KeyError, TypeError, AttributeError) as exc:
        raise Rejected("incomplete PR identity snapshot") from exc
    if (type(data[0]) is not int or data[0] != expected_pr_number or
            data[1] != expected_head or not _sha(data[1]) or
            type(data[2]) is not int or data[2] != REPO_ID or
            data[3] != REPOSITORY or data[4] != expected_base or
            not _sha(data[4]) or data[5] != "main" or
            type(data[6]) is not int or data[6] != REPO_ID or
            data[7] != REPOSITORY or data[8] != "open" or
            data[9] is not False or data[10] is not False):
        raise Rejected("PR head, base, repository or state mismatch")
    return data


@dataclass(frozen=True)
class UntrustedRaceCandidate:
    app_id: int
    installation_id: int
    check_id: int
    head_sha: str
    disposition: str = "SYNTHETIC_PREPOST_MATCH_NOT_AUTHORIZED"

    def as_dict(self) -> dict:
        return {
            "status": self.disposition,
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "check_id": self.check_id,
            "head_sha": self.head_sha,
            "provider_transport_authenticated": False,
            "app_credentials_authenticated": False,
            "operator_authorized": False,
            "freshness_independently_attested": False,
            "ruleset_enforcement_verified": False,
            "check_written": False,
            "merge_authorized": False,
        }


def compare_prepost_window(*,
                           pre_receipts: dict,
                           post_receipts: dict,
                           pr_before: dict,
                           pr_after: dict,
                           page_responses: list,
                           check_run_by_id: dict,
                           local_intent: dict,
                           expected_pr_number: int,
                           pinned_main_sha: str,
                           pinned_app_id: int,
                           pinned_installation_id: int,
                           started_at_utc: datetime,
                           finished_at_utc: datetime) -> UntrustedRaceCandidate:
    """Fail closed for structural race/drift, NEVER issue authorization.

    Each snapshot/clock/pin/receipt is caller-provided. This checks only
    internally consistent shape of simulated multi-GET responses.
    """
    if (not _sha(pinned_main_sha) or
            type(expected_pr_number) is not int or
            expected_pr_number <= 0):
        raise Rejected("invalid pinned PR/base identity")
    if (not isinstance(started_at_utc, datetime) or
            not isinstance(finished_at_utc, datetime) or
            started_at_utc.tzinfo is None or
            finished_at_utc.tzinfo is None or
            started_at_utc.utcoffset() is None or
            finished_at_utc.utcoffset() is None or
            started_at_utc.utcoffset().total_seconds() != 0 or
            finished_at_utc.utcoffset().total_seconds() != 0):
        raise Rejected("untrusted or non-UTC observation clock")
    duration = (finished_at_utc - started_at_utc).total_seconds()
    if duration <= 0 or duration > MAX_WINDOW_SECONDS:
        raise Rejected("observation window reversed or too long")

    # Both comparisons run *before* any synthetic check-run result is considered.
    a = inspect_installation_scope(
        receipts=pre_receipts,
        independently_pinned_app_id=pinned_app_id,
        independently_pinned_installation_id=pinned_installation_id,
        observed_at_utc=started_at_utc)
    b = inspect_installation_scope(
        receipts=post_receipts,
        independently_pinned_app_id=pinned_app_id,
        independently_pinned_installation_id=pinned_installation_id,
        observed_at_utc=finished_at_utc)
    if _canonical(pre_receipts) != _canonical(post_receipts) or a != b:
        raise Rejected("App installation or token scope drift")

    if type(local_intent) is not dict:
        raise Rejected("missing durable local intent")
    head = local_intent.get("head_sha")
    if not _sha(head):
        raise Rejected("invalid local intent HEAD")
    before = _pr_binding(pr_before, head, pinned_main_sha,
                         expected_pr_number)
    after = _pr_binding(pr_after, head, pinned_main_sha,
                        expected_pr_number)
    if before != after:
        raise Rejected("PR identity changed in readback window")
    result = compare_paginated_check_readback(
        page_responses=page_responses,
        local_intent=local_intent,
        live_pr_before=pr_before,
        live_pr_after=pr_after,
        check_run_by_id=check_run_by_id,
        expected_app_id=pinned_app_id)
    if result.app_id != a.app_id:
        raise Rejected("Check source and installation disagree")
    return UntrustedRaceCandidate(
        a.app_id, a.installation_id, result.observed_check_id, head)
