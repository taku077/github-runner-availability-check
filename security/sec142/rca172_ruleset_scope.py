"""RCA172: real public GitHub ruleset scope readback, not a write gate."""
import argparse
from datetime import datetime, timezone
import json
import sys
from urllib.request import Request, urlopen

REPO = "taku077/github-runner-availability-check"
BASE = "https://api.github.com/repos/" + REPO
PATHS = frozenset(("", "/rulesets?per_page=100", "/rulesets/27806733",
                   "/pulls/4", "/pulls/5"))
LIMIT = 2 * 1024 * 1024

class ScopeError(ValueError):
    pass

def public_get(path, opener=urlopen):
    if path not in PATHS:
        raise ScopeError("NON_ALLOWLISTED_PATH")
    req = Request(BASE + path, method="GET", headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pcfm-rca172-readonly"})
    with opener(req, timeout=15) as response:
        if response.geturl() != BASE + path:
            raise ScopeError("REDIRECT_NOT_ALLOWED")
        body = response.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ScopeError("TOO_LARGE")
    try:
        return json.loads(body)
    except (UnicodeError, ValueError) as exc:
        raise ScopeError("INVALID_JSON") from exc

def scope_assessment(data, observed_at_utc):
    if not isinstance(data, dict):
        raise ScopeError("INVALID_INPUT")
    try:
        dt = datetime.fromisoformat(observed_at_utc.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ScopeError("INVALID_OBSERVATION_TIME") from exc
    if dt.tzinfo is None or dt.utcoffset().total_seconds() != 0:
        raise ScopeError("NOT_UTC")
    repository = data.get("repository")
    if not isinstance(repository, dict) or repository.get("full_name") != REPO:
        raise ScopeError("REPOSITORY_MISMATCH")
    default = repository.get("default_branch")
    if default != "main":
        raise ScopeError("DEFAULT_BRANCH_CHANGED")
    all_rulesets = data.get("all_rulesets")
    if not isinstance(all_rulesets, list) or len(all_rulesets) >= 100:
        raise ScopeError("RULESETS_LIST_INCOMPLETE")
    if len(all_rulesets) != 1 or not isinstance(all_rulesets[0], dict):
        raise ScopeError("RULESET_SCOPE_UNDETERMINED")
    record = all_rulesets[0]
    if (record.get("id") != 27806733 or record.get("target") != "branch"
            or record.get("enforcement") != "active"):
        raise ScopeError("RULESET_UNEXPECTED")
    detail = data.get("ruleset")
    if not isinstance(detail, dict) or detail.get("id") != record["id"]:
        raise ScopeError("RULESET_DETAIL_MISMATCH")
    if detail.get("enforcement") != "active" or detail.get("target") != "branch":
        raise ScopeError("RULESET_DETAIL_UNEXPECTED")
    ref_names = detail.get("conditions", {}).get("ref_name", {})
    if ref_names.get("include") != ["~DEFAULT_BRANCH"] or ref_names.get("exclude") != []:
        raise ScopeError("NON_DEFAULT_ONLY_CONDITION")
    prs = {}
    for n in (4, 5):
        obj = data.get("pr" + str(n))
        if not isinstance(obj, dict) or obj.get("number") != n:
            raise ScopeError("PR_MISSING")
        head = obj.get("head")
        base = obj.get("base")
        if (not isinstance(head, dict) or not isinstance(base, dict)
                or not isinstance(head.get("repo"), dict)
                or head["repo"].get("full_name") != REPO
                or not isinstance(head.get("ref"), str)
                or head["ref"] == "" or head["ref"] == default
                or base.get("ref") != default):
            raise ScopeError("UNEXPECTED_PR_BRANCH")
        prs[str(n)] = {
            "branch": head["ref"],
            "within_this_default_only_ruleset": False,
            "direct_branch_write_denial_proven": False,
        }
    review_count = None
    for rule in detail.get("rules", []):
        if isinstance(rule, dict) and rule.get("type") == "pull_request":
            review_count = rule.get("parameters", {}).get("required_approving_review_count")
            break
    if type(review_count) is not int or review_count < 0:
        raise ScopeError("REVIEW_REQUIREMENT_UNKNOWN")
    return {
        "schema": "PCFM-RCA172-public-ruleset-scope-v1",
        "observed_at_utc": observed_at_utc,
        "repository": REPO,
        "default_branch": default,
        "checked_ruleset_id": 27806733,
        "known_active_rulesets_at_query": 1,
        "known_ruleset_target": "DEFAULT_BRANCH_ONLY",
        "main_within_this_ruleset": True,
        "required_reviews_for_main": review_count,
        "draft_pr_branches": prs,
        "meaning": "RULESET_APPLIES_TO_MAIN_NOT_THE_TWO_PR_BRANCHES",
        "native_chatgpt_direct_write_denied": "NOT_ESTABLISHED",
        "independent_external_writer": "NOT_IMPLEMENTED",
        "independent_user_or_third_party_attribution": "UNDETERMINED",
        "owner_confirmation_requested": False,
        "network_scope": "PUBLIC_GITHUB_GET_ONLY",
    }

def live():
    snap = {"repository": public_get(""),
            "all_rulesets": public_get("/rulesets?per_page=100"),
            "ruleset": public_get("/rulesets/27806733"),
            "pr4": public_get("/pulls/4"),
            "pr5": public_get("/pulls/5")}
    return scope_assessment(snap, datetime.now(timezone.utc).isoformat())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    if not args.live:
        raise SystemExit(2)
    try:
        result = live()
    except (ScopeError, OSError, ValueError) as exc:
        status = getattr(exc, "code", None)
        print("RCA172_LIVE_NOT_VERIFIED " + type(exc).__name__ +
              (" HTTP_STATUS=" + str(status) if status is not None else ""),
              file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
