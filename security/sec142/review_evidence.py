"""SEC152: conservative, offline GitHub PR-review evidence inventory.

No network, credentials, trusted identity source, approval or check publication.
All API-shaped pages, roster, clock and last-push evidence are caller-supplied.
A positive structural match never proves a human approved or authorizes merge.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from trusted_check_policy import Rejected
from provider_readback import SHA40
from installation_scope import REPOSITORY, REPO_ID

PAGE_SIZE = 100
MAX_PAGES = 10
REVIEW_STATES = frozenset(("APPROVED", "CHANGES_REQUESTED",
                            "DISMISSED", "COMMENTED"))
ELIGIBLE_ROLES = frozenset(("write", "maintain", "admin"))
LINK_RE = re.compile(r'<([^<>]+)>;\s*rel="(next|prev|first|last)"')


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _utc(value: Any) -> datetime:
    if type(value) is not str or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise Rejected("invalid UTC review timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Rejected("invalid UTC review timestamp") from exc
    return dt


def _url_page(value: Any, pr_number: int) -> int:
    if type(value) is not str:
        raise Rejected("missing PR-review request URL")
    try:
        p = urlsplit(value)
    except ValueError as exc:
        raise Rejected("unexpected PR-review host/path") from exc
    if (p.scheme != "https" or p.netloc != "api.github.com" or
            p.path != f"/repos/{REPOSITORY}/pulls/{pr_number}/reviews" or
            p.fragment):
        raise Rejected("unexpected PR-review host/path")
    try:
        pairs = parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise Rejected("invalid PR-review URL query") from exc
    if (len(pairs) != 2 or {a for a, _ in pairs} != {"per_page", "page"}):
        raise Rejected("ambiguous PR-review pagination query")
    q = dict(pairs)
    number = q["page"]
    if q["per_page"] != "100" or not number.isascii() or (
            not number.isdecimal()) or len(number) > 2 or (
            str(int(number)) != number) or int(number) < 1:
        raise Rejected("invalid PR-review page size/number")
    return int(number)


def _links(headers: Any, pr_number: int) -> dict:
    if type(headers) is not dict:
        raise Rejected("missing PR-review Link metadata")
    candidates = [v for k, v in headers.items()
                  if type(k) is str and k.lower() == "link"]
    if len(candidates) > 1:
        raise Rejected("ambiguous PR-review Link metadata")
    if not candidates or candidates[0] == "":
        return {}
    if type(candidates[0]) is not str:
        raise Rejected("invalid PR-review Link metadata")
    out: dict[str, int] = {}
    for fragment in candidates[0].split(","):
        m = LINK_RE.fullmatch(fragment.strip())
        if m is None:
            raise Rejected("malformed PR-review Link metadata")
        url, name = m.groups()
        if name in out:
            raise Rejected("duplicate PR-review Link relation")
        out[name] = _url_page(url, pr_number)
    return out


def _identity(user: Any) -> tuple[int, str]:
    if (type(user) is not dict or not _positive(user.get("id")) or
            type(user.get("login")) is not str or
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})",
                             user["login"]) or
            user.get("type") != "User"):
        raise Rejected("invalid GitHub reviewer identity")
    return (user["id"], user["login"].lower())


def _review(item: Any, observed_utc: datetime) -> tuple:
    if type(item) is not dict or not _positive(item.get("id")):
        raise Rejected("invalid review record ID")
    state = item.get("state")
    if type(state) is not str or state not in REVIEW_STATES:
        raise Rejected("unknown or unsubmitted review state")
    who = _identity(item.get("user"))
    sha = item.get("commit_id")
    if type(sha) is not str or not SHA40.fullmatch(sha):
        raise Rejected("invalid review commit SHA")
    ts = _utc(item.get("submitted_at"))
    if ts > observed_utc:
        raise Rejected("review submitted after observation")
    return item["id"], who[0], who[1], item["state"], sha, ts


def read_review_pages(*, pages: list, pr_number: int,
                      observed_at_utc: datetime) -> tuple[tuple, ...]:
    """Fail closed for missing/duplicate pages, records, states and ordering.

    GitHub's PR-review list is an ARRAY, not a total_count envelope.
    Link continuation is required for every nonfinal full 100-result page.
    There is no authenticated HTTP transport in this prototype.
    """
    if not _positive(pr_number):
        raise Rejected("invalid PR number")
    if (not isinstance(observed_at_utc, datetime) or
            observed_at_utc.tzinfo is None or
            observed_at_utc.utcoffset() is None or
            observed_at_utc.utcoffset().total_seconds() != 0):
        raise Rejected("observation must be UTC")
    if type(pages) is not list or not pages or len(pages) > MAX_PAGES:
        raise Rejected("missing or excessive PR-review pages")
    entries: list[tuple] = []
    ids: set[int] = set()
    logins: dict[str, int] = {}
    users: dict[int, str] = {}
    last_id = 0
    last_ts = None
    for index, page in enumerate(pages, start=1):
        if type(page) is not dict:
            raise Rejected("malformed PR-review response")
        if (type(page.get("status_code")) is not int or
                page["status_code"] != 200 or
                _url_page(page.get("request_url"), pr_number) != index):
            raise Rejected("PR-review page failed or reordered")
        rows = page.get("body")
        if type(rows) is not list or len(rows) > PAGE_SIZE:
            raise Rejected("invalid PR-review body")
        next_links = _links(page.get("headers"), pr_number)
        if index < len(pages):
            if next_links.get("next") != index + 1 or len(rows) != PAGE_SIZE:
                raise Rejected("missing or incomplete PR-review continuation")
        elif "next" in next_links:
            raise Rejected("unfetched PR-review continuation")
        for rel, expected in (("first", 1), ("prev", index - 1)):
            if rel in next_links and (expected < 1 or
                                      next_links[rel] != expected):
                raise Rejected("invalid PR-review Link relation")
        if "last" in next_links and next_links["last"] != len(pages):
            raise Rejected("unfetched PR-review last page")
        for item in rows:
            review = _review(item, observed_at_utc)
            rid, uid, login, _state, _head, ts = review
            if rid in ids or rid <= last_id or (
                    last_ts is not None and ts < last_ts):
                raise Rejected("duplicate or reordered review history")
            if (uid in users and users[uid] != login) or (
                    login in logins and logins[login] != uid):
                raise Rejected("ambiguous reviewer identity history")
            users[uid] = login
            logins[login] = uid
            ids.add(rid)
            last_id, last_ts = rid, ts
            entries.append(review)
    if len(entries) > PAGE_SIZE * MAX_PAGES:
        raise Rejected("oversized review history")
    return tuple(entries)


@dataclass(frozen=True)
class ReviewCandidate:
    reviewer_ids: tuple[int, ...]
    review_ids: tuple[int, ...]
    head_sha: str
    disposition: str = "SYNTHETIC_REVIEW_MATCH_NOT_AUTHORIZED"

    def as_dict(self) -> dict:
        return {
            "status": self.disposition,
            "reviewer_ids": list(self.reviewer_ids),
            "review_ids": list(self.review_ids),
            "head_sha": self.head_sha,
            "reviews_provider_authenticated": False,
            "actor_independence_attested": False,
            "operator_authorized": False,
            "merge_authorized": False,
            "check_written": False,
        }


def compare_review_history(*, pages_before: list, pages_after: list,
                           pr_number: int, head_sha: str,
                           author: dict, last_pusher: dict,
                           last_push_at_utc: str, allowed_reviewers: dict,
                           required_approvals: int,
                           started_at_utc: datetime,
                           finished_at_utc: datetime) -> ReviewCandidate:
    """Return structurally consistent candidate ONLY, NEVER authority.

    Last effective review per GitHub user governs our conservative local
    policy, with any CHANGES_REQUESTED treated as a global blocking signal.
    COMMENTS and DISMISSED supersede a prior APPROVED from the same account.
    GitHub role and human-independence assertions remain caller-controlled.
    """
    if type(head_sha) is not str or not SHA40.fullmatch(head_sha):
        raise Rejected("invalid review target HEAD")
    if (type(required_approvals) is not int or
            not 1 <= required_approvals <= 3):
        raise Rejected("invalid independent approval count")
    if (not isinstance(started_at_utc, datetime) or
            not isinstance(finished_at_utc, datetime) or
            started_at_utc.tzinfo is None or finished_at_utc.tzinfo is None or
            started_at_utc.utcoffset() is None or
            finished_at_utc.utcoffset() is None or
            started_at_utc.utcoffset().total_seconds() != 0 or
            finished_at_utc.utcoffset().total_seconds() != 0 or
            not 0 < (finished_at_utc - started_at_utc).total_seconds() <= 120):
        raise Rejected("invalid PR-review observation window")
    author_id, author_login = _identity(author)
    pusher_id, pusher_login = _identity(last_pusher)
    last_push_at = _utc(last_push_at_utc)
    if last_push_at > started_at_utc:
        raise Rejected("last push occurs after review observation")
    if (type(allowed_reviewers) is not dict or
            not required_approvals <= len(allowed_reviewers) <= 10):
        raise Rejected("missing independent reviewer roster")
    roster: dict[int, str] = {}
    for key, user in allowed_reviewers.items():
        if (type(key) is not str or not key.isascii() or
                not key.isdecimal() or str(int(key)) != key):
            raise Rejected("malformed roster user ID")
        uid, login = _identity(user)
        if uid != int(key) or user.get("permission") not in ELIGIBLE_ROLES:
            raise Rejected("roster ID or role mismatch")
        if (uid in (author_id, pusher_id) or
                login in (author_login, pusher_login)):
            raise Rejected("reviewer overlaps author or last pusher")
        if uid in roster:
            raise Rejected("duplicate trusted roster identity")
        roster[uid] = login

    earlier = read_review_pages(pages=pages_before, pr_number=pr_number,
                                observed_at_utc=started_at_utc)
    later = read_review_pages(pages=pages_after, pr_number=pr_number,
                              observed_at_utc=finished_at_utc)
    if earlier != later:
        raise Rejected("PR review history changed during readback")
    if not later:
        raise Rejected("no submitted PR review")
    final: dict[int, tuple] = {}
    # A COMMENTED or DISMISSED row is not independently authenticated
    # evidence that a prior CHANGES_REQUESTED was safely cleared.
    # Only a new explicit APPROVED on the current HEAD can clear it for
    # this conservative offline policy. GitHub's effective merge rules
    # still require independent provider evaluation.
    unresolved_requests: set[int] = set()
    for row in later:
        rid, uid, login, state, commit, ts = row
        if state == "CHANGES_REQUESTED":
            unresolved_requests.add(uid)
        elif state == "APPROVED" and commit == head_sha:
            unresolved_requests.discard(uid)
        final[uid] = row
    if unresolved_requests:
        raise Rejected("outstanding changes-requested review")
    chosen = []
    for uid, login in roster.items():
        row = final.get(uid)
        if row is not None and row[2] == login and row[3] == "APPROVED":
            if row[4] != head_sha or row[5] <= last_push_at:
                raise Rejected("stale approval or post-review push")
            chosen.append((uid, row[0]))
    if len(chosen) < required_approvals:
        raise Rejected("no sufficient current distinct approvals")
    chosen.sort()
    return ReviewCandidate(tuple(x[0] for x in chosen),
                           tuple(x[1] for x in chosen), head_sha)
