"""RCA175: fail-closed read backend, no arbitrary repo/ref/mutation."""
import unittest
import rca175_mirror_read_backend as m

class ReadBackendTests(unittest.TestCase):
    def test_immutable_baseline_only(self):
        m.valid_snapshot(m.SNAPSHOT_SHA)
        for bad in ("main", "HEAD", m.SNAPSHOT_SHA[:8], "a"*40, "--help", None):
            with self.subTest(bad=bad):
                with self.assertRaises(m.ReadRejected):
                    m.valid_snapshot(bad)
    def test_path_scope(self):
        self.assertEqual(m.valid_path("README.md"), "README.md")
        for bad in ("../README.md", "/etc/passwd", "README.md:other",
                    "README.md\x00", ".git/config", ".github/workflows/test.yml", None):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(m.ReadRejected, "PATH_NOT_ALLOWLISTED"):
                    m.valid_path(bad)
    def test_query_bounds(self):
        for bad in ("", "\n", "x"*61, 42, None):
            with self.subTest(bad=bad):
                with self.assertRaises(m.ReadRejected):
                    m.valid_query(bad)
    def test_query_normalization(self):
        self.assertEqual(m.valid_query("RUNNER"), "runner")
    def test_no_external_git_config(self):
        env=m.safe_git_environment({
            "PATH":"/usr/bin", "GITHUB_TOKEN":"x", "GH_TOKEN":"x",
            "GIT_SSH_COMMAND":"ssh -i /tmp/id", "GIT_CONFIG_PARAMETERS":"x",
            "GIT_CONFIG_COUNT":"1", "GIT_CONFIG_KEY_0":"x",
            "GIT_CONFIG_VALUE_0":"x", "LANG":"C"
        })
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("GIT_SSH_COMMAND", env)
        self.assertNotIn("GIT_CONFIG_PARAMETERS", env)
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"],"1")
    def test_mutations_denied_without_git_execution(self):
        class Trap:
            def __fspath__(self):
                raise AssertionError("mirror path evaluated")
        for op in ("write", "delete", "push", "update_ref",
                   "run_workflow", "create_file", None):
            with self.subTest(op=op):
                with self.assertRaisesRegex(m.ReadRejected, "OPERATION_DENIED"):
                    m.dispatch(Trap(), m.SNAPSHOT_SHA, op, {}, {})
    def test_unknown_params_denied(self):
        for op, args in (("fetch",{"path":"README.md","write":True}),
                         ("search",{"query":"runner","repo":"other"})):
            with self.subTest(op=op):
                with self.assertRaisesRegex(m.ReadRejected, "SCHEMA"):
                    m.dispatch(".", m.SNAPSHOT_SHA, op, args, {})
    def test_no_dynamic_repository_input(self):
        self.assertEqual(m.REPO, "taku077/github-runner-availability-check")
        self.assertNotIn("pcfm-forensic-dev", m.PUBLIC_REMOTE)
    def test_only_two_read_operations(self):
        self.assertEqual(m.ALLOWED_OPERATIONS, {"search","fetch"})
    def test_injection_before_git(self):
        with self.assertRaises(m.ReadRejected):
            m.dispatch("/no/mirror", m.SNAPSHOT_SHA,
                       "fetch", {"path":"README.md;git push"}, {})
    def test_missing_query_before_git(self):
        with self.assertRaises(m.ReadRejected):
            m.dispatch("/no/mirror", m.SNAPSHOT_SHA, "search", {}, {})

if __name__ == "__main__":
    unittest.main()
