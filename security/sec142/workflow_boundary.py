"""SEC156: conservative source-only audit of public GitHub Actions workflows.

This scanner is purposely NOT a complete YAML parser, GitHub server policy,
or separately governed security gate. It recognizes a small fixed workflow
subset and flags anything outside it for human review. It makes no network
calls, needs no secrets, and NEVER returns merge/check authorization.

The PR author can edit both this scanner and its CI test. As a result, even
zero structural findings cannot establish independent protection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)\s*(?:#.*)?$")
_EVENT = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):(?:\s*(?:#.*)?)?$")
_TOP = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):")
_PERMISSION = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):\s*(\S+)\s*(?:#.*)?$")
_ALLOWED_EVENTS = frozenset(("push", "pull_request", "workflow_dispatch"))
_ALLOWED_PERMISSIONS = {"contents": "read", "actions": "read"}
_UNSAFE_EVENT_DATA = re.compile(
    r"\$\{\{\s*(?:github\.event\b|github\.head_ref\b|github\.ref_name\b|"
    r"github\.event_name\b)", re.IGNORECASE
)
_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)",
                         re.IGNORECASE)
_MAX_BYTES = 64_000


@dataclass(frozen=True)
class WorkflowPreview:
    path: str
    events: tuple[str, ...]
    findings: tuple[str, ...]
    status: str = "PR_CONTROLLED_STATIC_PREVIEW_NOT_AUTHORIZED"

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "events": list(self.events),
            "findings": list(self.findings),
            "status": self.status,
            "yaml_fully_parsed": False,
            "provider_authenticated": False,
            "independent_policy_anchored": False,
            "independent_operator_attested": False,
            "merge_authorized": False,
            "check_written": False,
            "production_deployed": False,
        }


def _block(lines: list[str], start: int) -> list[str]:
    """Return lines until the next noncomment top-level mapping key."""
    collected = []
    for line in lines[start + 1:]:
        if line and not line.startswith((" ", "\t", "#")):
            break
        collected.append(line)
    return collected


def audit_workflow(path: Any, source: Any) -> WorkflowPreview:
    issues: set[str] = set()
    if (type(path) is not str or not path.startswith(".github/workflows/") or
            not path.endswith((".yml", ".yaml")) or
            path.count("/") != 2):
        path = "INVALID_WORKFLOW_PATH"
        issues.add("WORKFLOW_PATH_INVALID")
    if type(source) is not str or not source or len(source.encode(
            "utf-8", errors="replace")) > _MAX_BYTES:
        return WorkflowPreview(path, (), tuple(sorted(issues | {
            "WORKFLOW_SOURCE_MISSING_OR_OVERSIZED",
            "INDEPENDENT_TRUST_ROOT_NOT_PRESENT"})))
    if "\x00" in source or "\t" in source:
        issues.add("NONCANONICAL_WORKFLOW_SOURCE")
    lines = source.splitlines()
    text = "\n".join(line for line in lines
                     if not line.lstrip().startswith("#"))
    root = [(i, _TOP.match(line).group(1))
            for i, line in enumerate(lines) if _TOP.match(line)]
    events_start = [i for i, name in root if name == "on"]
    permissions_start = [i for i, name in root if name == "permissions"]
    if len(events_start) != 1 or lines[events_start[0]].strip() != "on:":
        issues.add("EVENT_MAPPING_UNVERIFIED")
        events: set[str] = set()
    else:
        on_block = _block(lines, events_start[0])
        event_names = set()
        for line in on_block:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.startswith("  ") and not line.startswith("   "):
                match = _EVENT.fullmatch(line)
                if match is None:
                    issues.add("UNSUPPORTED_EVENT_SYNTAX")
                else:
                    event_names.add(match.group(1))
        if not event_names:
            issues.add("EVENTS_NOT_DECLARED")
        if event_names - _ALLOWED_EVENTS:
            issues.add("PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW")
        events = event_names

    if len(permissions_start) != 1 or (
            lines[permissions_start[0]].strip() != "permissions:"):
        issues.add("ROOT_PERMISSIONS_NOT_EXPLICIT")
    else:
        permission_items = {}
        for line in _block(lines, permissions_start[0]):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.startswith("  ") and not line.startswith("   "):
                match = _PERMISSION.fullmatch(line)
                if match is None:
                    issues.add("UNSUPPORTED_PERMISSION_SYNTAX")
                else:
                    k, v = match.groups()
                    if k in permission_items:
                        issues.add("DUPLICATE_PERMISSION")
                    permission_items[k] = v
        if permission_items.get("contents") != "read":
            issues.add("CONTENTS_READ_SCOPE_NOT_PINNED")
        if any(k not in _ALLOWED_PERMISSIONS or
               v != _ALLOWED_PERMISSIONS.get(k)
               for k, v in permission_items.items()):
            issues.add("WORKFLOW_TOKEN_SCOPE_UNREVIEWED")
    if any(line.lstrip().startswith("permissions:")
           and not line.startswith("permissions:")
           for line in lines if not line.lstrip().startswith("#")):
        issues.add("JOB_PERMISSION_OVERRIDE_NEEDS_REVIEW")

    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = _USES.fullmatch(line)
        if "uses:" in line and re.match(r"^\s*(?:-\s*)?uses:", line):
            if match is None:
                issues.add("UNPARSEABLE_ACTION_REFERENCE")
            else:
                action = match.group(1)
                if ("@" not in action or "/" not in action.split("@", 1)[0]
                        or _SHA.fullmatch(action.rsplit("@", 1)[-1]) is None):
                    issues.add("ACTION_NOT_PINNED_BY_40_HEX_SHA")
                if action.startswith("actions/checkout@"):
                    # checkout may run on the untrusted PR preview branch:
                    # do not allow automatic token persistence.
                    tail = []
                    for candidate in lines[index + 1:index + 18]:
                        if re.match(r"^\s*-\s*(?:name|uses|run):", candidate):
                            break
                        tail.append(candidate)
                    if not any(re.fullmatch(r"\s+persist-credentials:\s*false\s*",
                                            candidate) for candidate in tail):
                        issues.add("CHECKOUT_CREDENTIAL_PERSISTENCE_NOT_DISABLED")
        for name in _SECRET_REF.findall(line):
            if name != "GITHUB_TOKEN":
                issues.add("NONDEFAULT_SECRET_REFERENCE")
    # Heuristic hard stop on untrusted GitHub expression directly included in
    # shell-run blocks. The scanner deliberately does not evaluate expressions.
    in_run = False
    run_indent = -1
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if in_run and indent <= run_indent:
            in_run = False
        if re.match(r"^\s*(?:-\s*)?run:\s*(?:\||>|.*)$", line):
            in_run = True
            run_indent = indent
        if in_run and _UNSAFE_EVENT_DATA.search(line):
            issues.add("UNTRUSTED_EXPRESSION_INTERPOLATED_IN_SHELL")

    # A YAML implementation could reinterpret duplicate/quoted/on-list keys.
    # Detect obvious unsupported alternate/alias forms; no claim of full
    # detection by regex. Real trust enforcement requires an independent parser.
    if re.search(r"(?m)^\s*(?:'on'|\"on\"|<<):", text):
        issues.add("UNSUPPORTED_YAML_MAPPING_OR_MERGE")
    if re.search(r"(?m)^\s*on:\s*(?:\[|\{|\*|&|!|[A-Za-z])", text):
        issues.add("UNSUPPORTED_INLINE_OR_ALIASED_EVENTS")
    if re.search(r"(?m)^\s*(?:pull_request_target|workflow_run|"
                 r"issue_comment|repository_dispatch):", text):
        issues.add("PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW")
    # App/Actions code controlled by this PR cannot become a trust anchor.
    issues.add("INDEPENDENT_TRUST_ROOT_NOT_PRESENT")
    return WorkflowPreview(path, tuple(sorted(events)), tuple(sorted(issues)))


def audit_checkout_workflows(repo_root: Path) -> tuple[WorkflowPreview, ...]:
    """Preview every checked-out YAML workflow in a bounded directory.

    The caller controls repo_root and its files. Never use this inventory to
    attest a GitHub repository state without independent source validation.
    """
    folder = repo_root / ".github" / "workflows"
    if not folder.is_dir():
        raise ValueError("workflow directory not available")
    paths = sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")])
    if not paths or len(paths) > 100:
        raise ValueError("unexpected workflow inventory")
    reports = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("unsupported workflow file entry")
        reports.append(audit_workflow(
            path.relative_to(repo_root).as_posix(),
            path.read_text(encoding="utf-8")))
    return tuple(reports)
