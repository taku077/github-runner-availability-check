"""SEC150 synthetic-only GitHub App / installation / token-scope tests.

All receipts are fabricated. No GitHub App is installed, no token is supplied,
and a structural match is never accepted as independent authorization.
"""
import copy
import unittest
from datetime import datetime, timedelta, timezone

from installation_scope import inspect_installation_scope
from trusted_check_policy import Rejected

NOW = datetime(2026, 11, 23, 0, 0, tzinfo=timezone.utc)
APP = 987654  # synthetic ID, not an installed App
INST = 123456  # synthetic ID, not an installed installation
OWNER = 344928446
REPO_ID = 1450293513
REPO = "taku077/github-runner-availability-check"
PERMS = {"checks": "write", "pull_requests": "read", "metadata": "read"}


def receipt(method, path, status, kind, body):
    return {"method": method, "path": path, "status_code": status,
            "credential_kind": kind, "body": body}


def fixture():
    return {
        "receipts": {
            "app": receipt("GET", "/app", 200, "app_jwt", {
                "id": APP, "slug": "fictional-pcfm-admission",
                "permissions": copy.deepcopy(PERMS)}),
            "installation": receipt(
                "GET", f"/app/installations/{INST}", 200, "app_jwt", {
                    "id": INST, "app_id": APP, "target_type": "User",
                    "target_id": OWNER, "repository_selection": "selected",
                    "suspended_at": None,
                    "account": {"login": "taku077", "id": OWNER,
                                "type": "User"},
                    "permissions": copy.deepcopy(PERMS)}),
            "repositories": receipt(
                "GET", "/installation/repositories", 200,
                "installation_token", {
                    "total_count": 1, "repositories": [
                        {"id": REPO_ID, "full_name": REPO, "private": False,
                         "owner": {"id": OWNER, "login": "taku077"}}]}),
            "scoped_token_metadata": receipt(
                "POST", f"/app/installations/{INST}/access_tokens",
                201, "app_jwt", {
                    "permissions": copy.deepcopy(PERMS),
                    "repositories": [{"id": REPO_ID, "full_name": REPO}],
                    "expires_at": "2026-11-23T00:30:00Z"}),
        },
        "independently_pinned_app_id": APP,
        "independently_pinned_installation_id": INST,
        "observed_at_utc": NOW,
    }


class InstallationScopeTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def body(self, name):
        return self.f["receipts"][name]["body"]

    def deny(self, pattern):
        with self.assertRaisesRegex(Rejected, pattern):
            inspect_installation_scope(**self.f)

    def test_perfect_synthetic_match_never_authorizes(self):
        result = inspect_installation_scope(**self.f).as_dict()
        self.assertEqual(result["status"],
                         "SYNTHETIC_SCOPE_MATCH_NOT_AUTHORIZED")
        self.assertFalse(result["app_authentication_verified"])
        self.assertFalse(result["installation_token_verified"])
        self.assertFalse(result["provider_responses_authenticated"])
        self.assertFalse(result["independent_operator_attested"])
        self.assertFalse(result["check_write_authorized"])
        self.assertFalse(result["merge_authorized"])
        self.assertFalse(result["ruleset_enforcement_verified"])

    def test_wrong_pinned_app_id(self):
        self.f["independently_pinned_app_id"] = APP + 1
        self.deny("GitHub App identity mismatch")

    def test_actions_app_cannot_be_pinned(self):
        self.f["independently_pinned_app_id"] = 15368
        self.deny("invalid or GitHub Actions")

    def test_boolean_pinned_app_rejected(self):
        self.f["independently_pinned_app_id"] = True
        self.deny("invalid or GitHub Actions")

    def test_boolean_pinned_installation_rejected(self):
        self.f["independently_pinned_installation_id"] = True
        self.deny("invalid or GitHub Actions")

    def test_missing_receipt(self):
        del self.f["receipts"]["app"]
        self.deny("incomplete or excessive")

    def test_extra_receipt(self):
        self.f["receipts"]["untrusted"] = {}
        self.deny("incomplete or excessive")

    def test_missing_app_body(self):
        del self.f["receipts"]["app"]["body"]
        self.deny("missing app response body")

    def test_no_clock_timezone(self):
        self.f["observed_at_utc"] = NOW.replace(tzinfo=None)
        self.deny("observation clock must be UTC")

    def test_local_clock_not_utc(self):
        self.f["observed_at_utc"] = NOW.astimezone(
            timezone(timedelta(hours=9)))
        self.deny("observation clock must be UTC")

    def test_wrong_app_id(self):
        self.body("app")["id"] = 23
        self.deny("GitHub App identity mismatch")

    def test_app_slug_actions(self):
        self.body("app")["slug"] = "github-actions"
        self.deny("GitHub App identity mismatch")

    def test_app_permissions_extra(self):
        self.body("app")["permissions"]["contents"] = "write"
        self.deny("App permissions")

    def test_app_permission_downgrade(self):
        self.body("app")["permissions"]["checks"] = "read"
        self.deny("App permissions")

    def test_missing_app_permission(self):
        del self.body("app")["permissions"]["pull_requests"]
        self.deny("App permissions")

    def test_wrong_installation_id(self):
        self.body("installation")["id"] += 1
        self.deny("installation identity")

    def test_wrong_installation_app(self):
        self.body("installation")["app_id"] = 15368
        self.deny("installation identity")

    def test_wrong_target_account_id(self):
        self.body("installation")["target_id"] = 999
        self.deny("installation identity")

    def test_target_type_not_user(self):
        self.body("installation")["target_type"] = "Organization"
        self.deny("installation identity")

    def test_installation_account_login(self):
        self.body("installation")["account"]["login"] = "other"
        self.deny("installation owner")

    def test_installation_account_id(self):
        self.body("installation")["account"]["id"] = 999
        self.deny("installation owner")

    def test_account_all_repositories_rejected(self):
        self.body("installation")["repository_selection"] = "all"
        self.deny("installation identity")

    def test_suspended_installation_rejected(self):
        self.body("installation")["suspended_at"] = "2026-11-01T00:00:00Z"
        self.deny("installation identity")

    def test_missing_suspension_state_rejected(self):
        del self.body("installation")["suspended_at"]
        self.deny("installation identity")

    def test_installation_overprivileged(self):
        self.body("installation")["permissions"]["administration"] = "write"
        self.deny("installation permissions")

    def test_repository_count_not_one(self):
        self.body("repositories")["total_count"] = 2
        self.deny("repository enumeration")

    def test_repository_entries_two(self):
        self.body("repositories")["repositories"].append(
            copy.deepcopy(self.body("repositories")["repositories"][0]))
        self.deny("repository enumeration")

    def test_repository_id_wrong(self):
        self.body("repositories")["repositories"][0]["id"] += 1
        self.deny("unexpected repository identity")

    def test_repository_path_wrong(self):
        self.body("repositories")["repositories"][0]["full_name"] = (
            "taku077/other-repo")
        self.deny("unexpected repository identity")

    def test_private_repo_flag_wrong(self):
        self.body("repositories")["repositories"][0]["private"] = True
        self.deny("unexpected repository identity")

    def test_repository_owner_wrong(self):
        self.body("repositories")["repositories"][0]["owner"]["id"] = 999
        self.deny("repository owner")

    def test_token_privilege_escalation(self):
        self.body("scoped_token_metadata")["permissions"][
            "pull_requests"] = "write"
        self.deny("scoped token permissions")

    def test_token_extra_permission(self):
        self.body("scoped_token_metadata")["permissions"][
            "workflows"] = "write"
        self.deny("scoped token permissions")

    def test_token_two_repositories(self):
        self.body("scoped_token_metadata")["repositories"].append(
            {"id": 5, "full_name": "other/other"})
        self.deny("token grants unexpected")

    def test_token_repo_wrong(self):
        self.body("scoped_token_metadata")["repositories"][0]["id"] = 2
        self.deny("token grants unexpected")

    def test_expired_token(self):
        self.body("scoped_token_metadata")["expires_at"] = (
            "2026-11-22T23:59:59Z")
        self.deny("expired or outside")

    def test_token_expires_within_two_minutes(self):
        self.body("scoped_token_metadata")["expires_at"] = (
            "2026-11-23T00:01:00Z")
        self.deny("expired or outside")

    def test_token_claims_more_than_hour(self):
        self.body("scoped_token_metadata")["expires_at"] = (
            "2026-11-23T01:00:01Z")
        self.deny("expired or outside")

    def test_expiry_non_utc_offset_rejected(self):
        self.body("scoped_token_metadata")["expires_at"] = (
            "2026-11-23T09:30:00+09:00")
        self.deny("non-UTC")

    def test_expiry_invalid_rejected(self):
        self.body("scoped_token_metadata")["expires_at"] = "not-a-timeZ"
        self.deny("invalid token expiration")

    def test_token_material_in_metadata_rejected(self):
        self.body("scoped_token_metadata")["token"] = "DO_NOT_SEND"
        self.deny("secret or token material")

    def test_private_key_material_rejected(self):
        self.body("app")["private_key"] = "DO_NOT_SEND"
        self.deny("secret or token material")

    def test_nested_secret_rejected(self):
        self.body("installation")["account"]["secret"] = "DO_NOT_SEND"
        self.deny("secret or token material")

    def test_false_boolean_http_status_rejected(self):
        self.f["receipts"]["app"]["status_code"] = True
        self.deny("endpoint, status or credential")

    def test_token_http_error_rejected(self):
        self.f["receipts"]["scoped_token_metadata"]["status_code"] = 403
        self.deny("endpoint, status or credential")

    def test_wrong_app_auth_kind_rejected(self):
        self.f["receipts"]["app"]["credential_kind"] = (
            "installation_token")
        self.deny("endpoint, status or credential")

    def test_wrong_repo_auth_kind_rejected(self):
        self.f["receipts"]["repositories"]["credential_kind"] = "app_jwt"
        self.deny("endpoint, status or credential")

    def test_wrong_access_token_endpoint_rejected(self):
        self.f["receipts"]["scoped_token_metadata"]["path"] += "/wrong"
        self.deny("endpoint, status or credential")

    def test_wrong_app_endpoint_rejected(self):
        self.f["receipts"]["app"]["path"] = "/user"
        self.deny("endpoint, status or credential")


if __name__ == "__main__":
    unittest.main()
