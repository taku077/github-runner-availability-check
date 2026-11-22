"""SEC150: untrusted GitHub App installation provenance and scope preflight.

No HTTP, JWT, private key, token, signing, check publication or merge authorization.
The receipts, independently pinned IDs and even the clock are provided by the
caller and are NOT provider- or operator-attested by this offline code.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from trusted_check_policy import Rejected

REPOSITORY = "taku077/github-runner-availability-check"
REPO_ID = 1450293513
OWNER_ID = 344928446
ACTIONS_APP_ID = 15368
EXPECTED_PERMISSION_SET = {"checks": "write", "pull_requests": "read",
                           "metadata": "read"}
_RECEIPT_KINDS = {
    "app": ("GET", "/app", 200, "app_jwt"),
    "installation": ("GET", "/app/installations/{installation_id}",
                     200, "app_jwt"),
    "repositories": ("GET", "/installation/repositories", 200,
                     "installation_token"),
    "scoped_token_metadata": (
        "POST", "/app/installations/{installation_id}/access_tokens",
        201, "app_jwt"),
}
_FORBIDDEN_KEYS = {"token", "jwt", "authorization", "private_key", "secret",
                   "password", "client_secret", "access_token", "pem"}


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _no_credentials(item: Any) -> None:
    """Keep this offline fixture interface free of credential material."""
    if isinstance(item, dict):
        for key, val in item.items():
            if type(key) is not str:
                raise Rejected("invalid metadata key type")
            if key.lower() in _FORBIDDEN_KEYS:
                raise Rejected("secret or token material is prohibited")
            _no_credentials(val)
    elif isinstance(item, list):
        for val in item:
            _no_credentials(val)


def _permission_subset(item: Any, context: str) -> None:
    # Conservative v1 policy: exactly the three minimal grants. Any
    # additional grant, even a read-only one, requires a design review.
    if type(item) is not dict or item != EXPECTED_PERMISSION_SET:
        raise Rejected(f"{context} permissions differ from minimal scope")


def _receipt(receipts: dict, name: str, installation_id: int) -> dict:
    item = receipts.get(name)
    if type(item) is not dict:
        raise Rejected("missing or malformed " + name + " receipt")
    method, path, code, cred = _RECEIPT_KINDS[name]
    path = path.format(installation_id=installation_id)
    if (item.get("method") != method or item.get("path") != path or
            type(item.get("status_code")) is not int or
            item.get("status_code") != code or
            item.get("credential_kind") != cred):
        raise Rejected(name + " endpoint, status or credential kind mismatch")
    body = item.get("body")
    if type(body) is not dict:
        raise Rejected("missing " + name + " response body")
    return body


def _timestamp(value: Any) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise Rejected("non-UTC token expiration")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Rejected("invalid token expiration") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise Rejected("non-UTC token expiration")
    return parsed


@dataclass(frozen=True)
class UntrustedInstallationCandidate:
    app_id: int
    installation_id: int
    repository_id: int
    expiration: str
    disposition: str = "SYNTHETIC_SCOPE_MATCH_NOT_AUTHORIZED"

    def as_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "repository_id": self.repository_id,
            "expires_at": self.expiration,
            "status": self.disposition,
            "app_authentication_verified": False,
            "independent_operator_attested": False,
            "installation_token_verified": False,
            "provider_responses_authenticated": False,
            "check_write_authorized": False,
            "merge_authorized": False,
            "ruleset_enforcement_verified": False,
        }


def inspect_installation_scope(*, receipts: dict,
                               independently_pinned_app_id: int,
                               independently_pinned_installation_id: int,
                               observed_at_utc: datetime
                               ) -> UntrustedInstallationCandidate:
    """Reject mismatched, overprivileged, stale or inconsistent snapshots.

    The pinned IDs/receipts/clock are caller-provided *claims*. No offline
    comparison can establish their independent origin or the user's intent.
    """
    if (not _positive(independently_pinned_app_id) or
            independently_pinned_app_id == ACTIONS_APP_ID or
            not _positive(independently_pinned_installation_id)):
        raise Rejected("invalid or GitHub Actions App identity")
    if (not isinstance(observed_at_utc, datetime) or
            observed_at_utc.tzinfo is None or
            observed_at_utc.utcoffset() is None or
            observed_at_utc.utcoffset().total_seconds() != 0):
        raise Rejected("observation clock must be UTC")
    if type(receipts) is not dict or set(receipts) != set(_RECEIPT_KINDS):
        raise Rejected("incomplete or excessive provider receipts")
    _no_credentials(receipts)

    app = _receipt(receipts, "app", independently_pinned_installation_id)
    if (not _positive(app.get("id")) or
            app["id"] != independently_pinned_app_id or
            not isinstance(app.get("slug"), str) or not app["slug"] or
            app["slug"] == "github-actions"):
        raise Rejected("GitHub App identity mismatch")
    _permission_subset(app.get("permissions"), "App")

    inst = _receipt(receipts, "installation",
                    independently_pinned_installation_id)
    if (not _positive(inst.get("id")) or
            inst["id"] != independently_pinned_installation_id or
            type(inst.get("app_id")) is not int or
            inst["app_id"] != independently_pinned_app_id or
            inst.get("target_type") != "User" or
            inst.get("target_id") != OWNER_ID or
            inst.get("repository_selection") != "selected" or
            inst.get("suspended_at", "missing") is not None):
        raise Rejected("installation identity, scope or state mismatch")
    owner = inst.get("account")
    if (type(owner) is not dict or owner.get("login") != "taku077" or
            owner.get("id") != OWNER_ID or owner.get("type") != "User"):
        raise Rejected("installation owner mismatch")
    _permission_subset(inst.get("permissions"), "installation")

    repos = _receipt(receipts, "repositories",
                     independently_pinned_installation_id)
    entries = repos.get("repositories")
    if (type(repos.get("total_count")) is not int or
            repos.get("total_count") != 1 or
            type(entries) is not list or len(entries) != 1):
        raise Rejected("repository enumeration is not the sole target")
    found = entries[0]
    if (type(found) is not dict or found.get("id") != REPO_ID or
            type(found.get("id")) is not int or
            found.get("full_name") != REPOSITORY or
            found.get("private") is not False):
        raise Rejected("unexpected repository identity")
    repo_owner = found.get("owner")
    if (type(repo_owner) is not dict or
            repo_owner.get("id") != OWNER_ID or
            repo_owner.get("login") != "taku077"):
        raise Rejected("repository owner mismatch")

    # The host must strip the secret token before passing this normalized
    # metadata. It must independently bind both API routes to the same
    # authenticated App / installation, which this function cannot prove.
    tok = _receipt(receipts, "scoped_token_metadata",
                   independently_pinned_installation_id)
    _permission_subset(tok.get("permissions"), "scoped token")
    names = tok.get("repositories")
    if (type(names) is not list or len(names) != 1 or
            type(names[0]) is not dict or names[0].get("id") != REPO_ID or
            type(names[0].get("id")) is not int or
            names[0].get("full_name") != REPOSITORY):
        raise Rejected("token grants unexpected repository scope")
    expiration = _timestamp(tok.get("expires_at"))
    seconds = (expiration - observed_at_utc).total_seconds()
    if not 120 <= seconds <= 3600:
        raise Rejected("token metadata is expired or outside safe lifetime")

    return UntrustedInstallationCandidate(
        independently_pinned_app_id, independently_pinned_installation_id,
        REPO_ID, tok["expires_at"])
