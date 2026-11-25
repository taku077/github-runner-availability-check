"""RCA174: ensure provider git probe never uses private/writable transport."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import rca174_public_mirror as mirror

class ReadOnlyMirrorTests(unittest.TestCase):
    def test_only_fixed_public_remote(self):
        commands=mirror.command_argv("demo.git","demo.bundle")
        self.assertEqual(commands[0][-2],mirror.PUBLIC_REMOTE)
        self.assertNotIn("pcfm-forensic-dev",str(commands))
        self.assertFalse(any(x in ("push","update-ref","receive-pack") for c in commands for x in c))
    def test_no_credentials_in_environment(self):
        env=mirror.git_environment({"GITHUB_TOKEN":"secret","GH_TOKEN":"secret",
                    "GIT_ASKPASS":"custom-askpass","GIT_SSH_COMMAND":"ssh -i key",
                    "GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"http.extraheader",
                    "GIT_CONFIG_VALUE_0":"authorization: secret","LANG":"C"})
        self.assertNotIn("GITHUB_TOKEN",env)
        self.assertNotIn("GH_TOKEN",env)
        self.assertNotIn("GIT_SSH_COMMAND",env)
        self.assertNotIn("GIT_CONFIG_KEY_0",env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"],"0")
        self.assertEqual(env["LANG"],"C")
    def test_command_sequence(self):
        cmds=mirror.command_argv("mirror.git","snapshot.bundle")
        self.assertEqual([c[3] for c in cmds],
                         ["clone","fsck","rev-parse","for-each-ref","bundle","bundle"])
        self.assertEqual(cmds[-1][-2:],["verify","snapshot.bundle"])
    def test_local_hash(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/"source.bundle"
            path.write_bytes(b"RCA174-test-only")
            sha,n=mirror.sha256_file(path)
            self.assertEqual(n,len(b"RCA174-test-only"))
            self.assertEqual(len(sha),64)
    def test_bundle_size_limit(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/"oversize"
            previous=mirror.MAX_BUNDLE_BYTES
            try:
                mirror.MAX_BUNDLE_BYTES=10
                path.write_bytes(b"X"*11)
                with self.assertRaisesRegex(mirror.MirrorError,"LIMIT"):
                    mirror.sha256_file(path)
            finally:
                mirror.MAX_BUNDLE_BYTES=previous
    def test_no_private_mode(self):
        with self.assertRaises(SystemExit):
            mirror.main([])
    def test_only_known_public_url(self):
        self.assertTrue(mirror.PUBLIC_REMOTE.endswith("github-runner-availability-check.git"))
        self.assertFalse("@" in mirror.PUBLIC_REMOTE)

if __name__=="__main__":
    unittest.main()
