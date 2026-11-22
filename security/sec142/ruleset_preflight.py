"""SEC154: read-only, fail-closed GitHub Ruleset / PR / Check preflight.

Checks API-shaped *untrusted* observations against stricter acceptance criteria.
No REST calls, HTTP auth, App keys, secrets, Check Run writes or merges.
Even a structurally perfect future configuration is NOT accepted as
independently enforced without an external operator and negative live tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

REPOSITORY = "taku077/github-runner-availability-check"
REPOSITORY_ID = 1450293513
RULESET_ID = 27806733
GITHUB_ACTIONS_APP_ID = 15368
INDEPENDENT_CHECK = "pcfm-independent-admission"
ACTIONS_CHECK = "env003-main-rules"
_SHA_DIGITS = frozenset("0123456789abcdef")


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _sha(value: Any) -> bool:
    return (type(value) is str and len(value) == 40 and
            all(c in _SHA_DIGITS for c in value))


def _object(value: Any) -> dict:
    return value if type(value) is dict else {}


def _array(value: Any) -> list:
    return value if type(value) is list else []


def _source_app(value: Any) -> bool:
    return _positive(value) and value != GITHUB_ACTIONS_APP_ID


@dataclass(frozen=True)
class RuleAudit:
    findings: tuple[str, ...]
    rule_id: int
    observed_head: str | None
    status: str = "READONLY_PREFLIGHT_NOT_ACCEPTED"

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": list(self.findings),
            "ruleset_id": self.rule_id,
            "head_sha": self.observed_head,
            "source_is_independent": False,
            "operator_identity_attested": False,
            "reviewer_human_independence_attested": False,
            "live_negative_merge_test_passed": False,
            "api_transport_authenticated_by_separate_host": False,
            "independent_enforcement_accepted": False,
            "check_written": False,
            "merge_authorized": False,
            "production_deployed": False,
        }


def audit_readonly_gate(*, repository: Any, ruleset: Any,
                        pull_request: Any, reviews: Any,
                        check_run_list: Any,
                        independently_pinned_app_id: Any = None) -> RuleAudit:
    """Produce deterministic, bounded findings; NEVER a success approval.

    All observations, including the expected App ID, can be forged or stale.
    Live test results and owner authorization must be proven by a different,
    independently controlled system; no API-shaped dictionary can do that.
    """
    reasons: set[str] = set()
    repo = _object(repository)
    rules = _object(ruleset)
    pr = _object(pull_request)
    if not (_positive(repo.get("id")) and
            repo["id"] == REPOSITORY_ID and
            repo.get("full_name") == REPOSITORY and
            _object(repo.get("owner")).get("type") == "User"):
        reasons.add("TARGET_REPOSITORY_NOT_VERIFIED")
    if (type(ruleset) is not dict or
            type(rules.get("id")) is not int or
            rules["id"] != RULESET_ID or
            rules.get("source_type") != "Repository" or
            rules.get("source") != REPOSITORY or
            rules.get("target") != "branch"):
        reasons.add("RULESET_IDENTITY_NOT_VERIFIED")
    if rules.get("enforcement") != "active":
        reasons.add("RULESET_NOT_ACTIVE")
    cond = _object(rules.get("conditions"))
    names = _object(cond.get("ref_name"))
    if (names.get("include") != ["~DEFAULT_BRANCH"] or
            names.get("exclude") != []):
        reasons.add("DEFAULT_BRANCH_SCOPE_UNVERIFIED")
    if type(rules.get("bypass_actors")) is not list or rules["bypass_actors"]:
        reasons.add("RULESET_BYPASS_NOT_EXCLUDED")

    entries = rules.get("rules")
    if type(entries) is not list or not entries:
        reasons.add("RULE_DEFINITIONS_MISSING")
        entries = []
    by_type: dict[str, dict] = {}
    for item in entries:
        if (type(item) is not dict or
                type(item.get("type")) is not str or
                item["type"] in by_type):
            reasons.add("AMBIGUOUS_RULE_DEFINITIONS")
            continue
        by_type[item["type"]] = item
    for required in ("non_fast_forward", "deletion", "pull_request",
                     "required_status_checks"):
        if required not in by_type:
            reasons.add("REQUIRED_BRANCH_RULE_MISSING")

    pr_rule = _object(by_type.get("pull_request"))
    params = _object(pr_rule.get("parameters"))
    count = params.get("required_approving_review_count")
    if not (_positive(count) and count <= 6):
        reasons.add("REVIEW_APPROVAL_MINIMUM_MISSING")
    if params.get("dismiss_stale_reviews_on_push") is not True:
        reasons.add("STALE_REVIEW_DISMISSAL_NOT_ENFORCED")
    if params.get("require_last_push_approval") is not True:
        reasons.add("LAST_PUSH_INDEPENDENT_APPROVAL_NOT_REQUIRED")
    if params.get("required_review_thread_resolution") is not True:
        reasons.add("REVIEW_THREAD_RESOLUTION_NOT_REQUIRED")

    status_rule = _object(by_type.get("required_status_checks"))
    status = _object(status_rule.get("parameters"))
    if status.get("strict_required_status_checks_policy") is not True:
        reasons.add("STATUS_CHECK_BRANCH_FRESHNESS_NOT_REQUIRED")
    if status.get("do_not_enforce_on_create") is not False:
        reasons.add("STATUS_CHECK_ENFORCEMENT_SCOPE_WEAK")
    requirements = status.get("required_status_checks")
    if type(requirements) is not list or not requirements:
        reasons.add("REQUIRED_STATUS_CHECKS_MISSING")
        requirements = []

    if not _source_app(independently_pinned_app_id):
        reasons.add("INDEPENDENT_APP_NOT_PINNED")
    independent = []
    checked = set()
    for requirement in requirements:
        item = _object(requirement)
        name, origin = item.get("context"), item.get("integration_id")
        if (type(name) is not str or not name or name in checked or
                not _positive(origin)):
            reasons.add("INVALID_OR_DUPLICATE_REQUIRED_CHECK")
            continue
        checked.add(name)
        if name == INDEPENDENT_CHECK:
            independent.append(item)
            if (not _source_app(origin) or
                    origin != independently_pinned_app_id):
                reasons.add("INDEPENDENT_CHECK_SOURCE_NOT_PINNED")
    if len(independent) != 1:
        reasons.add("INDEPENDENT_CHECK_NOT_REQUIRED")

    head = _object(pr.get("head"))
    base = _object(pr.get("base"))
    actual_head = head.get("sha")
    if not (_sha(actual_head) and
            type(pr.get("number")) is int and pr["number"] > 0 and
            pr.get("state") == "open" and pr.get("draft") is False and
            pr.get("merged") is False and
            _object(head.get("repo")).get("id") == REPOSITORY_ID and
            base.get("ref") == "main" and _sha(base.get("sha")) and
            _object(base.get("repo")).get("id") == REPOSITORY_ID):
        reasons.add("PR_NOT_ELIGIBLE_FOR_LIVE_ENFORCEMENT")

    review_rows = reviews
    if type(review_rows) is not list or len(review_rows) > 1000:
        reasons.add("PR_REVIEW_COLLECTION_INCOMPLETE")
        review_rows = []
    approved_ids: set[int] = set()
    submitter = _object(pr.get("user")).get("id")
    for review in review_rows:
        item = _object(review)
        uid = _object(item.get("user")).get("id")
        if (item.get("state") == "APPROVED" and
                _positive(uid) and uid != submitter and
                item.get("commit_id") == actual_head):
            approved_ids.add(uid)
    if not (_positive(count) and len(approved_ids) >= count):
        reasons.add("CURRENT_SHA_APPROVALS_NOT_OBSERVED")

    check_obj = _object(check_run_list)
    total, check_rows = check_obj.get("total_count"), check_obj.get("check_runs")
    if (type(total) is not int or not 0 <= total <= 1000 or
            type(check_rows) is not list or len(check_rows) != total):
        reasons.add("CHECK_RUN_COLLECTION_INCOMPLETE")
        check_rows = []
    matching = []
    check_ids = set()
    for row in check_rows:
        item = _object(row)
        cid = item.get("id")
        if not _positive(cid) or cid in check_ids:
            reasons.add("CHECK_RUN_IDENTITY_AMBIGUOUS")
            continue
        check_ids.add(cid)
        if item.get("name") == INDEPENDENT_CHECK:
            matching.append(item)
    if len(matching) != 1:
        reasons.add("INDEPENDENT_CHECK_RUN_NOT_OBSERVED")
    else:
        item = matching[0]
        app_id = _object(item.get("app")).get("id")
        if (not _source_app(app_id) or
                app_id != independently_pinned_app_id or
                item.get("head_sha") != actual_head or
                item.get("status") != "completed" or
                item.get("conclusion") != "success"):
            reasons.add("INDEPENDENT_CHECK_RUN_SOURCE_OR_STATE_UNVERIFIED")
    # User approval & API/host identity have no proof even with perfect JSON.
    reasons.add("EXTERNAL_OPERATOR_AND_PROVIDER_AUTHENTICATION_NOT_PROVEN")
    reasons.add("LIVE_REJECTION_TEST_NOT_PROVEN")
    return RuleAudit(tuple(sorted(reasons)), RULESET_ID,
                     actual_head if _sha(actual_head) else None)
