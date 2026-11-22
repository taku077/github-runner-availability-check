"""SEC149: offline, fail-closed Check Runs REST pagination envelope validation.

Inputs are caller-provided and UNTRUSTED. This module performs no network
requests, authenticates no API responses and cannot authorize a merge.
A future separately governed App host must obtain and attest the responses.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from provider_readback import REPOSITORY, SHA40, compare_check_readback
from trusted_check_policy import Rejected

_PAGE_SIZE = 100
_MAX_TOTAL = 1000
_LINK = re.compile(r'<([^<>]+)>;\s*rel="(next|prev|first|last)"')


def _page_from_url(url: object, head_sha: str, repository: str) -> int:
    if type(url) is not str:
        raise Rejected("missing or invalid API URL")
    parts = urlsplit(url)
    expected_path = f"/repos/{repository}/commits/{head_sha}/check-runs"
    if (parts.scheme != "https" or parts.netloc != "api.github.com" or
            parts.path != expected_path or parts.fragment):
        raise Rejected("untrusted API URL, host or ref")
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True,
                          strict_parsing=True)
    except ValueError as exc:
        raise Rejected("invalid API query parameters") from exc
    if len(pairs) != 3 or {key for key, _ in pairs} != {
            "filter", "per_page", "page"}:
        raise Rejected("missing, extra or duplicate API query parameter")
    values = dict(pairs)
    if values["filter"] != "all" or values["per_page"] != str(_PAGE_SIZE):
        raise Rejected("API filtering or page size differs")
    number = values["page"]
    if not number.isascii() or not number.isdecimal() or (
            str(int(number)) != number or int(number) < 1):
        raise Rejected("invalid API page number")
    return int(number)


def _link_targets(headers: dict, head_sha: str, repository: str) -> dict:
    if not isinstance(headers, dict):
        raise Rejected("missing response headers")
    candidates = [value for key, value in headers.items()
                  if isinstance(key, str) and key.lower() == "link"]
    if len(candidates) > 1:
        raise Rejected("ambiguous Link header")
    if not candidates or candidates[0] == "":
        return {}
    value = candidates[0]
    if type(value) is not str:
        raise Rejected("invalid Link header")
    targets = {}
    for piece in value.split(","):
        match = _LINK.fullmatch(piece.strip())
        if match is None:
            raise Rejected("malformed Link header")
        url, rel = match.groups()
        if rel in targets:
            raise Rejected("duplicate pagination relation")
        targets[rel] = _page_from_url(url, head_sha, repository)
    return targets


def flatten_check_run_pages(*, page_responses: list, head_sha: str,
                            repository: str = REPOSITORY) -> dict:
    """Validate page envelope/order/count; return a synthetic list response.

    Require exact SHA-ref URLs, filter=all, per_page=100, all numbered pages,
    stable total_count, correct page length and Link next/last relations.
    This is NOT a provider-attested or atomic API snapshot.
    """
    if (repository != REPOSITORY or type(head_sha) is not str or
            SHA40.fullmatch(head_sha) is None):
        raise Rejected("invalid repository or head")
    if (not isinstance(page_responses, list) or not page_responses or
            len(page_responses) > _MAX_TOTAL // _PAGE_SIZE):
        raise Rejected("missing or excessive API pages")

    all_runs: list = []
    total = None
    expected_pages = None
    for number, response in enumerate(page_responses, start=1):
        if not isinstance(response, dict):
            raise Rejected("malformed API page envelope")
        if response.get("status_code") != 200 or (
                type(response.get("status_code")) is not int):
            raise Rejected("non-success API response")
        requested_page = _page_from_url(response.get("request_url"),
                                        head_sha, repository)
        if requested_page != number:
            raise Rejected("missing, duplicated or reordered page")
        body = response.get("body")
        if not isinstance(body, dict):
            raise Rejected("missing API response body")
        count, runs = body.get("total_count"), body.get("check_runs")
        if (type(count) is not int or count <= 0 or count > _MAX_TOTAL or
                not isinstance(runs, list)):
            raise Rejected("invalid API total_count or check_runs")
        if total is None:
            total = count
            expected_pages = (total + _PAGE_SIZE - 1) // _PAGE_SIZE
        elif count != total:
            raise Rejected("total_count changed during pagination")
        if number > expected_pages:
            raise Rejected("excess page")
        expected_count = min(_PAGE_SIZE, total - len(all_runs))
        if len(runs) != expected_count:
            raise Rejected("partial, missing or excessive page records")
        links = _link_targets(response.get("headers"), head_sha, repository)
        if number < expected_pages:
            if links.get("next") != number + 1:
                raise Rejected("missing or incorrect next page link")
        elif "next" in links:
            raise Rejected("unexpected next page link")
        for relation, correct in (
                ("first", 1), ("last", expected_pages),
                ("prev", number - 1)):
            if relation in links and (
                    links[relation] != correct or correct < 1):
                raise Rejected("inconsistent pagination Link relation")
        all_runs.extend(runs)

    if len(page_responses) != expected_pages or len(all_runs) != total:
        raise Rejected("incomplete API page set")
    return {"total_count": total, "check_runs": all_runs}


def compare_paginated_check_readback(*, page_responses: list,
                                     local_intent: dict,
                                     live_pr_before: dict,
                                     live_pr_after: dict,
                                     check_run_by_id: dict,
                                     expected_app_id: int,
                                     repository: str = REPOSITORY):
    """Link SEC149 envelope checks to SEC147 strict identity comparison.

    Return value is always the synthetic NOT_AUTHORIZED disposition.
    """
    if not isinstance(local_intent, dict):
        raise Rejected("invalid local intent")
    head_sha = local_intent.get("head_sha")
    pages = flatten_check_run_pages(
        page_responses=page_responses, head_sha=head_sha,
        repository=repository)
    return compare_check_readback(
        local_intent=local_intent, live_pr_before=live_pr_before,
        live_pr_after=live_pr_after, check_run_by_id=check_run_by_id,
        check_run_list=pages, expected_app_id=expected_app_id,
        repository=repository)
