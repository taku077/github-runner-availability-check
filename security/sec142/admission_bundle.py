"""SEC153: non-authorizing offline composition of SEC151 and SEC152.

A passing synthetic set means ONLY that its caller-supplied objects are
internally consistent. It does not authenticate GitHub, prove distinct humans,
verify a third-party operator, issue a check, or permit a PR merge.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from prepost_consistency import compare_prepost_window
from review_evidence import compare_review_history
from trusted_check_policy import Rejected
from installation_scope import REPOSITORY, REPO_ID

_APP_KEYS = frozenset((
    "pre_receipts", "post_receipts", "pr_before", "pr_after",
    "page_responses", "check_run_by_id", "local_intent",
    "expected_pr_number", "pinned_main_sha", "pinned_app_id",
    "pinned_installation_id", "started_at_utc", "finished_at_utc",
))
_REVIEW_KEYS = frozenset((
    "pages_before", "pages_after", "pr_number", "head_sha", "author",
    "last_pusher", "last_push_at_utc", "allowed_reviewers",
    "required_approvals", "started_at_utc", "finished_at_utc",
))


def _user_identity(data: Any) -> tuple[int, str]:
    if (type(data) is not dict or type(data.get("id")) is not int or
            data["id"] <= 0 or type(data.get("login")) is not str or
            not data["login"].strip() or
            data.get("type") != "User"):
        raise Rejected("missing or malformed PR submitter identity")
    return data["id"], data["login"].lower()


def _time(data: Any) -> str:
    if (not isinstance(data, datetime) or data.tzinfo is None or
            data.utcoffset() is None or
            data.utcoffset().total_seconds() != 0):
        raise Rejected("non-UTC bundle timestamp")
    return data.isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class UntrustedAdmissionBundle:
    app_id: int
    installation_id: int
    check_id: int
    reviewer_ids: tuple[int, ...]
    review_ids: tuple[int, ...]
    head_sha: str
    metadata_sha256: str
    disposition: str = "SYNTHETIC_BUNDLE_NOT_AUTHORIZED"

    def as_dict(self):
        return {
            "status": self.disposition,
            "repository": REPOSITORY,
            "head_sha": self.head_sha,
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "check_id": self.check_id,
            "reviewer_ids": list(self.reviewer_ids),
            "review_ids": list(self.review_ids),
            "metadata_sha256": self.metadata_sha256,
            "digest_is_signature": False,
            "api_authenticated": False,
            "reviewer_human_independence_verified": False,
            "operator_authorized": False,
            "ruleset_enforcement_verified": False,
            "check_written": False,
            "merge_authorized": False,
        }


def compare_synthetic_admission_bundle(*,
                                       app_window: dict,
                                       review_window: dict
                                       ) -> UntrustedAdmissionBundle:
    """Conservative read-only cross-check; never generate an ALLOW.

    Three temporal constraints:
    1. Independent reviewer snapshot starts before the App/check snapshot.
    2. Reviewer snapshot finishes after the App/check snapshot.
    3. Both windows are at most 120 seconds (checked by their evaluators).
    These are caller-clock checks, not atomic, not cryptographic evidence.
    """
    if (type(app_window) is not dict or set(app_window) != _APP_KEYS or
            type(review_window) is not dict or
            set(review_window) != _REVIEW_KEYS):
        raise Rejected("missing or excessive admission bundle evidence")
    for name in ("started_at_utc", "finished_at_utc"):
        _time(app_window[name])
        _time(review_window[name])
    if (review_window["started_at_utc"] > app_window["started_at_utc"] or
            review_window["finished_at_utc"] <
            app_window["finished_at_utc"]):
        raise Rejected("review freshness window does not enclose Check readback")

    # Cross-bind the PR submitter, which SEC151 intentionally does not
    # otherwise check. GitHub PR submitter != necessarily commit author;
    # neither identifies the actual person controlling an account.
    before = app_window.get("pr_before")
    after = app_window.get("pr_after")
    if type(before) is not dict or type(after) is not dict:
        raise Rejected("missing PR submitter records")
    submitter_a = _user_identity(before.get("user"))
    submitter_b = _user_identity(after.get("user"))
    reviewer_author = _user_identity(review_window["author"])
    if (submitter_a != submitter_b or
            submitter_a != reviewer_author):
        raise Rejected("PR submitter and review author provenance mismatch")

    if (review_window["pr_number"] != app_window["expected_pr_number"] or
            type(review_window["pr_number"]) is not int or
            review_window["head_sha"] !=
            app_window["local_intent"].get("head_sha") or
            before.get("number") != review_window["pr_number"] or
            before.get("head", {}).get("repo", {}).get("id") != REPO_ID):
        raise Rejected("bundle PR/HEAD/repository binding mismatch")

    # Both are UNTRUSTED structural comparisons. Do not infer source
    # authenticity or approval from their return types.
    app = compare_prepost_window(**app_window)
    review = compare_review_history(**review_window)
    if review.head_sha != app.head_sha:
        raise Rejected("review and check HEAD differ")

    # Reproducibility-only summary commitment, no independent signature.
    # We deliberately avoid serializing raw API bodies, login names, tokens
    # or reviewer profile metadata. It is not tamper-evident without an
    # external authenticated channel and independently pinned anchor.
    summary = {
        "domain": "pcfm-sec153-synthetic-untrusted-v1",
        "repo_id": REPO_ID,
        "pr": app_window["expected_pr_number"],
        "base": app_window["pinned_main_sha"],
        "head": app.head_sha,
        "app_id": app.app_id,
        "installation_id": app.installation_id,
        "check_id": app.check_id,
        "reviewer_ids": list(review.reviewer_ids),
        "review_ids": list(review.review_ids),
        "app_start_utc": _time(app_window["started_at_utc"]),
        "app_end_utc": _time(app_window["finished_at_utc"]),
        "review_start_utc": _time(review_window["started_at_utc"]),
        "review_end_utc": _time(review_window["finished_at_utc"]),
    }
    digest = hashlib.sha256(json.dumps(summary, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True)
                           .encode("ascii")).hexdigest()
    return UntrustedAdmissionBundle(
        app.app_id, app.installation_id, app.check_id,
        review.reviewer_ids, review.review_ids, app.head_sha, digest)
