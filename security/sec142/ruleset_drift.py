"""SEC155: offline drift check over paired, untrusted GitHub observations.

This is a structural, read-only *quarantine* function for future independently
operated collectors. No GitHub network request, App identity, reviewer identity,
signature, token, check creation, Ruleset edit or merge authorization.

Two identical forged snapshots can pass the drift comparison. Never use this
code or its SHA-256 as independent evidence of origin or enforcement.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ruleset_preflight import audit_readonly_gate
from trusted_check_policy import Rejected

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_ALLOWED = frozenset(("repository", "ruleset", "pull_request", "reviews",
                      "check_run_list", "main_head_sha"))
_MAX_BYTES = 180_000
_MAX_WINDOW = 120


def _valid_sha(value: Any) -> bool:
    return type(value) is str and _SHA40.fullmatch(value) is not None


def _utc(when: Any) -> None:
    if (not isinstance(when, datetime) or when.tzinfo is None or
            when.utcoffset() is None or
            when.utcoffset().total_seconds() != 0):
        raise Rejected("UTC observation clock required")


def _canon(data: Any) -> bytes:
    try:
        raw = json.dumps(data, sort_keys=True, ensure_ascii=True,
                         allow_nan=False, separators=(",", ":")).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise Rejected("unserializable or unsafe snapshot") from exc
    if len(raw) > _MAX_BYTES:
        raise Rejected("oversized snapshot is not admissible")
    return raw


def _shape(observation: Any) -> dict:
    if type(observation) is not dict or set(observation) != _ALLOWED:
        raise Rejected("incomplete or excessive GitHub readback fields")
    if not _valid_sha(observation["main_head_sha"]):
        raise Rejected("malformed public main HEAD")
    if (type(observation["repository"]) is not dict or
            type(observation["ruleset"]) is not dict or
            type(observation["pull_request"]) is not dict or
            type(observation["reviews"]) is not list or
            type(observation["check_run_list"]) is not dict):
        raise Rejected("invalid GitHub readback body types")
    _canon(observation)
    return observation


@dataclass(frozen=True)
class UntrustedDriftReport:
    findings: tuple[str, ...]
    digest_sha256: str
    status: str = "READONLY_DRIFT_PREFLIGHT_NOT_AUTHORIZED"

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": list(self.findings),
            "comparison_digest_sha256": self.digest_sha256,
            "digest_is_external_signature": False,
            "provider_authenticated": False,
            "independent_operator_attested": False,
            "independent_enforcement_verified": False,
            "check_written": False,
            "merge_authorized": False,
            "production_deployed": False,
        }


def audit_paired_readbacks(*, before: Any, after: Any,
                           independently_pinned_app_id: Any,
                           expected_main_head_sha: Any,
                           started_at_utc: datetime,
                           finished_at_utc: datetime) -> UntrustedDriftReport:
    """Return a *negative-only* status after comprehensive drift checks.

    All values including the clock, pinned App ID, and both snapshots come
    from the caller. Real accepted evidence requires external authenticated
    collection, distinct human review and authorized rejection demonstrations.
    """
    _utc(started_at_utc)
    _utc(finished_at_utc)
    secs = (finished_at_utc - started_at_utc).total_seconds()
    if secs <= 0 or secs > _MAX_WINDOW:
        raise Rejected("observation window reversed or too long")
    if not _valid_sha(expected_main_head_sha):
        raise Rejected("invalid independently pinned main HEAD")
    a, b = _shape(before), _shape(after)
    findings = set()
    if a["main_head_sha"] != expected_main_head_sha or (
            b["main_head_sha"] != expected_main_head_sha):
        findings.add("BASE_SHA_CHANGED_OR_PIN_MISMATCH")
    if _canon(a["repository"]) != _canon(b["repository"]):
        findings.add("REPOSITORY_IDENTITY_DRIFT")
    if _canon(a["ruleset"]) != _canon(b["ruleset"]):
        findings.add("RULESET_CHANGED_DURING_COLLECTION")
    if _canon(a["pull_request"]) != _canon(b["pull_request"]):
        findings.add("PULL_REQUEST_CHANGED_DURING_COLLECTION")
    if _canon(a["reviews"]) != _canon(b["reviews"]):
        findings.add("REVIEWS_CHANGED_DURING_COLLECTION")
    if _canon(a["check_run_list"]) != _canon(b["check_run_list"]):
        findings.add("CHECK_RUNS_CHANGED_DURING_COLLECTION")
    for snapshot in (a, b):
        policy = audit_readonly_gate(
            repository=snapshot["repository"],
            ruleset=snapshot["ruleset"],
            pull_request=snapshot["pull_request"],
            reviews=snapshot["reviews"],
            check_run_list=snapshot["check_run_list"],
            independently_pinned_app_id=independently_pinned_app_id)
        findings.update("GATE_" + name for name in policy.findings)
    # No trust-root or App signature exists in the public PR-controlled
    # source; these MUST be blockers even with two matching snapshots.
    findings.update({
        "EXTERNAL_POLICY_AND_OPERATOR_NOT_ATTESTED",
        "REAL_RULESET_REJECTION_AND_RECOVERY_NOT_TESTED",
        "AUTHENTICATED_PROVIDER_COLLECTION_NOT_IMPLEMENTED",
    })
    digest = hashlib.sha256(
        b"PCFM-SEC155-READONLY-UNTRUSTED-V1\x00" + _canon(a)
        + b"\x00" + _canon(b)
    ).hexdigest()
    return UntrustedDriftReport(tuple(sorted(findings)), digest)
