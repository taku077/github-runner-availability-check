"""SEC142 source-only reviewer evidence policy; NOT an enforcement service.

In an actual GitHub App, the caller MUST independently authenticate and
retrieve provider state; all caller-supplied dictionaries here are untrusted.
This module never emits GitHub checks, never merges and never accesses tokens.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

EXPECTED_REPOSITORY = "taku077/github-runner-availability-check"
EXPECTED_BASE = "main"
RESERVED_CHECK = "pcfm-independent-admission"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
PERMITTED_ROLES = frozenset({"write", "maintain", "admin"})


class Rejected(ValueError):
    pass


def _sha(value: Any) -> bool:
    return isinstance(value, str) and SHA40.fullmatch(value) is not None


def verify_webhook(body: bytes, signature: str, secret: bytes) -> dict:
    """Validate webhook raw bytes before parsing. Replay requires external durable ledger."""
    if not isinstance(body, bytes) or not body or len(body) > 1_000_000:
        raise Rejected("invalid webhook body")
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise Rejected("invalid secret configuration")
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        raise Rejected("invalid signature format")
    correct = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(correct, signature):
        raise Rejected("invalid signature")
    try:
        result = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected("invalid JSON") from exc
    if not isinstance(result, dict):
        raise Rejected("invalid payload")
    return result


@dataclass(frozen=True)
class Decision:
    status: str
    reasons: tuple[str, ...]
    head_sha: str | None = None

    def as_dict(self) -> dict:
        return {"status": self.status, "reasons": list(self.reasons),
                "head_sha": self.head_sha, "check_written": False,
                "enforcement": "NOT_DEPLOYED"}


def evaluate_candidate(event: dict, live: dict) -> Decision:
    """Only a candidate decision. Never treat JSON arguments as authenticated by this function.

    A separate trusted host must validate webhook signature AND replay defense,
    fetch the latest PR, exact file list, role and review records independently,
    bind all reads to one current revision, and use an independently protected
    GitHub App with checks:write to publish a check. No such host exists yet.
    """
    problems: list[str] = []
    try:
        if event["repository"]["full_name"] != EXPECTED_REPOSITORY:
            problems.append("WRONG_REPOSITORY")
        if live["repository"] != EXPECTED_REPOSITORY:
            problems.append("WRONG_LIVE_REPOSITORY")
        ep = event["pull_request"]
        number = event["number"]
        if type(number) is not int or number <= 0 or live["number"] != number:
            problems.append("PR_NUMBER_MISMATCH")
        event_head = ep["head"]["sha"]
        current_head = live["head_sha"]
        event_base = ep["base"]["sha"]
        current_base = live["base_sha"]
        if not all(_sha(x) for x in (event_head, current_head, event_base, current_base)):
            problems.append("INVALID_SHA")
        if event_head != current_head or event_base != current_base:
            problems.append("STALE_EVENT_OR_PR")
        if (ep["base"]["ref"] != EXPECTED_BASE or live["base_ref"] != EXPECTED_BASE):
            problems.append("WRONG_BASE_REF")
        if ep["base"]["repo"]["full_name"] != EXPECTED_REPOSITORY:
            problems.append("WRONG_BASE_REPOSITORY")
        if ep["user"]["login"] != live["author"]:
            problems.append("AUTHOR_CHANGED")
        if ep.get("draft", False) or live.get("draft", False):
            problems.append("DRAFT_PR")
        paths = live["files"]
        if not isinstance(paths, list) or not paths or len(paths) > 500 or (
                any(not isinstance(p, str) or not p or p.startswith("/") or
                    ".." in p.split("/") for p in paths)) or len(set(paths)) != len(paths):
            problems.append("INVALID_FILE_SET")
        if live["changed_files"] != len(paths):
            problems.append("FILE_COUNT_MISMATCH")
        reviews = live["reviews"]
        if not isinstance(reviews, list):
            problems.append("INVALID_REVIEW_LIST")
            reviews = []
        approvals = []
        for r in reviews:
            if (isinstance(r, dict) and r.get("state") == "APPROVED" and
                    r.get("commit_id") == current_head and
                    isinstance(r.get("login"), str) and
                    r.get("login") != live["author"] and
                    r.get("permission") in PERMITTED_ROLES):
                approvals.append(r["login"])
        if not approvals:
            problems.append("NO_ELIGIBLE_CURRENT_HEAD_REVIEW")
        # A separate human/authority must attest distinct-actor independence;
        # GitHub account names and role metadata do not establish human identity.
        if not live.get("independent_operator_attestation_verified", False):
            problems.append("OPERATOR_INDEPENDENCE_NOT_ATTESTED")
        # The attestation flag alone is NOT proof: the host must verify its
        # origin cryptographically outside this PR-controlled module.
    except (KeyError, TypeError, AttributeError, ValueError):
        problems.append("INCOMPLETE_OR_MALFORMED_EVIDENCE")
        current_head = None
    if problems:
        return Decision("BLOCK", tuple(sorted(set(problems))),
                        current_head if _sha(current_head) else None)
    # Deliberately no PASS/ALLOW. Only an independently controlled App service
    # with verified inputs may decide whether to emit a trusted check-run.
    return Decision("CANDIDATE_ONLY_NOT_ENFORCED",
                    ("EXTERNAL_GITHUB_APP_AND_ATTESTED_INPUTS_REQUIRED",),
                    current_head)


def signed_fixture(event: dict, secret: bytes) -> tuple[bytes, str]:
    """Synthetic testing helper only. Never use a real credential."""
    raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return raw, "sha256=" + hmac.new(secret, raw, hashlib.sha256).hexdigest()
