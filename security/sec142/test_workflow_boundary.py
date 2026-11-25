"""SEC156: checked-out public workflows and adversarial source mutations.

All test code executes in PR-controlled Actions; a green job cannot attest
independent GitHub App authorization or a non-bypassable gate.
"""
from pathlib import Path
import tempfile
import unittest

from workflow_boundary import audit_workflow, audit_checkout_workflows

ROOT = Path(__file__).resolve().parents[2]
PATH = ".github/workflows/sec142-external-admission-prototype.yml"
SOURCE = (ROOT / PATH).read_text(encoding="utf-8")
CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


class WorkflowBoundaryTests(unittest.TestCase):
    def check(self, source=SOURCE, *needs):
        obj = audit_workflow(PATH, source).as_dict()
        self.assertEqual(obj["status"],
                         "PR_CONTROLLED_STATIC_PREVIEW_NOT_AUTHORIZED")
        self.assertFalse(obj["yaml_fully_parsed"])
        self.assertFalse(obj["provider_authenticated"])
        self.assertFalse(obj["independent_policy_anchored"])
        self.assertFalse(obj["independent_operator_attested"])
        self.assertFalse(obj["merge_authorized"])
        self.assertFalse(obj["check_written"])
        self.assertFalse(obj["production_deployed"])
        self.assertIn("INDEPENDENT_TRUST_ROOT_NOT_PRESENT",
                      obj["findings"])
        for flag in needs:
            self.assertIn(flag, obj["findings"])
        return obj

    def test_13_actual_checked_out_workflows(self):
        results = audit_checkout_workflows(ROOT)
        self.assertEqual(len(results), 13)
        self.assertIn(PATH, [r.path for r in results])
        for item in results:
            with self.subTest(path=item.path):
                self.assertEqual(
                    item.findings, ("INDEPENDENT_TRUST_ROOT_NOT_PRESENT",))
                self.assertFalse(item.as_dict()["merge_authorized"])

    def test_current_sec142_preview_is_not_independent(self):
        obj = self.check()
        self.assertEqual(obj["events"],
                         ["pull_request", "workflow_dispatch"])
        self.assertEqual(obj["findings"],
                         ["INDEPENDENT_TRUST_ROOT_NOT_PRESENT"])

    def test_comment_only_not_a_privileged_trigger(self):
        self.check(SOURCE + "\n# pull_request_target: not an event\n")

    def test_wrong_path_triggers_review(self):
        obj = audit_workflow("README.md", SOURCE).as_dict()
        self.assertIn("WORKFLOW_PATH_INVALID", obj["findings"])

    def test_empty_workflow_fails_closed(self):
        self.check("", "WORKFLOW_SOURCE_MISSING_OR_OVERSIZED")

    def test_oversized_workflow_fails_closed(self):
        self.check(SOURCE + "X"*66000,
                   "WORKFLOW_SOURCE_MISSING_OR_OVERSIZED")

    def test_unsupported_repo_without_workflow_dir(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                audit_checkout_workflows(Path(folder))


MUTANTS = [
    ("pull_request_target", "  pull_request:", "  pull_request_target:",
     "PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW"),
    ("workflow_run", "  pull_request:", "  workflow_run:",
     "PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW"),
    ("issue_comment", "  pull_request:", "  issue_comment:",
     "PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW"),
    ("repo_dispatch", "  pull_request:", "  repository_dispatch:",
     "PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW"),
    ("unknown_event", "  pull_request:", "  security_future_event:",
     "PRIVILEGED_OR_UNKNOWN_EVENT_REQUIRES_REVIEW"),
    ("on_inline", "on:\n", "on: [pull_request]\n",
     "EVENT_MAPPING_UNVERIFIED"),
    ("on_alias", "on:\n", "on: *other\n",
     "UNSUPPORTED_INLINE_OR_ALIASED_EVENTS"),
    ("on_quoted", "on:\n", "'on':\n",
     "UNSUPPORTED_YAML_MAPPING_OR_MERGE"),
    ("duplicate_on", "on:\n", "on:\n  pull_request:\non:\n",
     "EVENT_MAPPING_UNVERIFIED"),
    ("no_root_perms", "permissions:\n", "old_permissions:\n",
     "ROOT_PERMISSIONS_NOT_EXPLICIT"),
    ("permissions_write", "contents: read", "contents: write",
     "WORKFLOW_TOKEN_SCOPE_UNREVIEWED"),
    ("id_token_write", "  contents: read",
     "  contents: read\n  id-token: write",
     "WORKFLOW_TOKEN_SCOPE_UNREVIEWED"),
    ("checks_write", "  contents: read",
     "  contents: read\n  checks: write",
     "WORKFLOW_TOKEN_SCOPE_UNREVIEWED"),
    ("duplicate_permission", "  contents: read",
     "  contents: read\n  contents: read",
     "DUPLICATE_PERMISSION"),
    ("job_permission_override", "    runs-on: ubuntu-24.04",
     "    permissions:\n      contents: write\n    runs-on: ubuntu-24.04",
     "JOB_PERMISSION_OVERRIDE_NEEDS_REVIEW"),
    ("unpinned_action_tag", CHECKOUT_SHA, "v4",
     "ACTION_NOT_PINNED_BY_40_HEX_SHA"),
    ("unpinned_action_branch", CHECKOUT_SHA, "main",
     "ACTION_NOT_PINNED_BY_40_HEX_SHA"),
    ("local_action", "actions/checkout@", "./relative-action@",
     "ACTION_NOT_PINNED_BY_40_HEX_SHA"),
    ("checkout_creds_true", "persist-credentials: false",
     "persist-credentials: true",
     "CHECKOUT_CREDENTIAL_PERSISTENCE_NOT_DISABLED"),
    ("checkout_creds_omitted", "persist-credentials: false",
     "other: false",
     "CHECKOUT_CREDENTIAL_PERSISTENCE_NOT_DISABLED"),
    ("nondefault_secret",
     "run: python3 -m unittest",
     "run: echo ${{ secrets.DEPLOYMENT_KEY }} # python3 -m unittest",
     "NONDEFAULT_SECRET_REFERENCE"),
    ("pr_title_in_shell",
     "run: python3 -m unittest",
     'run: echo "${{ github.event.pull_request.title }}" # python3 -m unittest',
     "UNTRUSTED_EXPRESSION_INTERPOLATED_IN_SHELL"),
    ("head_ref_in_shell",
     "run: python3 -m unittest",
     'run: echo "${{ github.head_ref }}" # python3 -m unittest',
     "UNTRUSTED_EXPRESSION_INTERPOLATED_IN_SHELL"),
    ("event_body_in_shell",
     "run: python3 -m unittest",
     'run: echo "${{ github.event.issue.body }}" # python3 -m unittest',
     "UNTRUSTED_EXPRESSION_INTERPOLATED_IN_SHELL"),
    ("unparseable_action",
     "uses: actions/checkout@"+CHECKOUT_SHA,
     "uses: >\n          actions/checkout@"+CHECKOUT_SHA,
     "ACTION_NOT_PINNED_BY_40_HEX_SHA"),
    ("root_missing_contents",
     "contents: read", "metadata: read",
     "CONTENTS_READ_SCOPE_NOT_PINNED"),
    ("root_inline_permissions",
     "permissions:\n", "permissions: write-all\n",
     "ROOT_PERMISSIONS_NOT_EXPLICIT"),
]
for name, old, new, expected in MUTANTS:
    def factory(before=old, after=new, reason=expected):
        def test(self):
            self.assertIn(before, SOURCE)
            variant = SOURCE.replace(before, after, 1)
            self.check(variant, reason)
        return test
    setattr(WorkflowBoundaryTests, "test_mutation_" + name, factory())


if __name__ == "__main__":
    unittest.main()
