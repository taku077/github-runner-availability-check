"""RCA181 public synthetic prototype; NOT an independent anchor or production gate.
Only ephemeral keys, local SQLite, synthetic bytes. No credentials or network.
"""
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import threading
import unittest

DOMAIN = "pcfm-rca181-public-fixture-v1"
ZERO = "0" * 64
FIELDS = {"domain", "generation", "previous", "digest", "kid"}
MAX = 65536


class Denied(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise Denied("duplicate field")
        obj[k] = v
    return obj


def openssl(args):
    return subprocess.run(["openssl", *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=10, check=False)


def make_envelope(key, n, previous, state):
    meta = canonical(dict(domain=DOMAIN, generation=n, previous=previous,
                          digest=digest(state), kid="test-key"))
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "meta").write_bytes(meta)
        result = openssl(["pkeyutl", "-sign", "-inkey", str(key), "-rawin",
                          "-in", str(p / "meta")])
        if result.returncode or len(result.stdout) != 64:
            raise RuntimeError("test signing failed")
        return meta, result.stdout, state


def verify(public, envelope):
    try:
        raw, sig, state = envelope
        if not all(type(x) is bytes for x in envelope):
            raise Denied("type")
        if not 0 < len(raw) <= 2048 or len(sig) != 64 or not 0 < len(state) <= MAX:
            raise Denied("size")
        obj = json.loads(raw, object_pairs_hook=unique)
        if type(obj) is not dict or set(obj) != FIELDS or canonical(obj) != raw:
            raise Denied("schema")
        n = obj["generation"]
        if type(n) is not int or not 1 <= n <= 2**53-1:
            raise Denied("generation")
        if obj["domain"] != DOMAIN or obj["kid"] != "test-key":
            raise Denied("scope/key")
        for field in ("previous", "digest"):
            if type(obj[field]) is not str or not re.fullmatch("[0-9a-f]{64}", obj[field]):
                raise Denied("digest shape")
        if obj["digest"] != digest(state):
            raise Denied("state digest")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "meta").write_bytes(raw)
            (p / "sig").write_bytes(sig)
            result = openssl(["pkeyutl", "-verify", "-pubin", "-inkey", str(public),
                              "-rawin", "-in", str(p / "meta"), "-sigfile", str(p / "sig")])
            if result.returncode:
                raise Denied("signature")
        return obj
    except (ValueError, TypeError, OSError, subprocess.SubprocessError) as e:
        raise Denied("invalid envelope") from e


def connect(db):
    c = sqlite3.connect(db, timeout=10, isolation_level=None)
    c.execute("PRAGMA synchronous=FULL")
    return c


def init(db):
    with connect(db) as c:
        c.execute("CREATE TABLE history (generation INTEGER PRIMARY KEY, digest TEXT NOT NULL, "
                  "meta BLOB NOT NULL, sig BLOB NOT NULL, state BLOB NOT NULL)")


def advance(db, public, expected, envelope, crash=None):
    obj = verify(public, envelope)
    c = connect(db)
    try:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT generation,digest FROM history ORDER BY generation DESC LIMIT 1").fetchone()
        current = tuple(row) if row else (0, ZERO)
        if current != expected or obj["generation"] != current[0]+1 or obj["previous"] != current[1]:
            raise Denied("CAS or chain")
        c.execute("INSERT INTO history VALUES (?, ?, ?, ?, ?)",
                  (obj["generation"], obj["digest"], *envelope))
        if crash == "before_commit":
            os._exit(41)
        c.commit()
        if crash == "after_commit":
            os._exit(42)
        return obj["generation"], obj["digest"]
    finally:
        c.close()


def read_current(db, public):
    try:
        with connect(db) as c:
            row = c.execute("SELECT generation,digest,meta,sig,state FROM history "
                            "ORDER BY generation DESC LIMIT 1").fetchone()
        if row is None:
            raise Denied("missing anchor")
        env = tuple(row[2:])
        obj = verify(public, env)
        if (obj["generation"], obj["digest"]) != tuple(row[:2]):
            raise Denied("anchor mismatch")
        return env
    except (OSError, sqlite3.Error) as e:
        raise Denied("anchor unavailable") from e


def accept(db, public, candidate):
    verify(public, candidate)
    if candidate != read_current(db, public):
        raise Denied("not current")
    return candidate[2]


def recover(db, public, cache):
    env = read_current(db, public)
    fd, name = tempfile.mkstemp(dir=cache.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(env[2])
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, cache)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    if cache.read_bytes() != read_current(db, public)[2]:
        raise Denied("recovery changed")
    return env


class RCA181SignedGeneration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key, self.pub = self.root/"test.key", self.root/"test.pub"
        self.assertEqual(openssl(["genpkey", "-algorithm", "ED25519", "-out", str(self.key)]).returncode, 0)
        self.assertEqual(openssl(["pkey", "-in", str(self.key), "-pubout", "-out", str(self.pub)]).returncode, 0)
        self.db = self.root/"test.sqlite"
        init(self.db)
        self.old = make_envelope(self.key, 1, ZERO, b"synthetic-old")
        self.anchor = advance(self.db, self.pub, (0, ZERO), self.old)
        self.new = make_envelope(self.key, 2, self.anchor[1], b"synthetic-new")

    def commit(self):
        return advance(self.db, self.pub, self.anchor, self.new)

    def test_A01_current_signed(self):
        self.commit()
        self.assertEqual(accept(self.db, self.pub, self.new), b"synthetic-new")

    def test_A02_old_valid_signature_rejected(self):
        self.commit()
        with self.assertRaises(Denied):
            accept(self.db, self.pub, self.old)

    def test_A03_tamper(self):
        for candidate in [(self.new[0], self.new[1], b"tampered"),
                          (self.new[0], b"x"*64, self.new[2]),
                          (self.new[0].replace(b"test-key", b"bad-key!"), self.new[1], self.new[2]),
                          (self.new[0].replace(b"public-fixture", b"wrong-environm"), self.new[1], self.new[2]),
                          (b'{"generation":1,"generation":2}', self.new[1], self.new[2])]:
            with self.subTest(candidate=candidate[0]), self.assertRaises(Denied):
                advance(self.db, self.pub, self.anchor, candidate)
        self.assertEqual(read_current(self.db, self.pub), self.old)

    def test_A03_flying_generation_wrong_chain(self):
        for n, prev in [(3,self.anchor[1]),(2,ZERO),(1,ZERO)]:
            with self.subTest(n=n, prev=prev), self.assertRaises(Denied):
                advance(self.db,self.pub,self.anchor,make_envelope(self.key,n,prev,b"fixture"))
        self.assertEqual(read_current(self.db,self.pub),self.old)

    def test_A03_same_generation_fork(self):
        self.commit()
        other = make_envelope(self.key,2,self.anchor[1],b"fork")
        with self.assertRaises(Denied):
            accept(self.db,self.pub,other)

    def test_A04_two_writers_one_commit(self):
        other = make_envelope(self.key,2,self.anchor[1],b"concurrent")
        barrier = threading.Barrier(2, timeout=10)
        outcomes = []
        def writer(env):
            barrier.wait()
            try:
                advance(self.db,self.pub,self.anchor,env)
                outcomes.append("commit")
            except Denied:
                outcomes.append("deny")
        threads = [threading.Thread(target=writer,args=(env,)) for env in (self.new,other)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
            self.assertFalse(t.is_alive())
        self.assertCountEqual(outcomes,["commit","deny"])
        self.assertIn(read_current(self.db,self.pub),(self.new,other))

    def test_A05_missing_anchor(self):
        with self.assertRaises(Denied):
            accept(self.root/"missing.sqlite",self.pub,self.old)

    def test_A05_corrupt_anchor_payload(self):
        self.commit()
        with connect(self.db) as c:
            c.execute("UPDATE history SET state=? WHERE generation=2",(b"bad",))
        with self.assertRaises(Denied):
            accept(self.db,self.pub,self.new)

    def crash(self, point, expected_code):
        p = mp.get_context("spawn").Process(target=advance,
            args=(self.db,self.pub,self.anchor,self.new,point))
        p.start()
        p.join(20)
        if p.is_alive():
            p.kill()
            p.join()
            self.fail("child timeout")
        self.assertEqual(p.exitcode,expected_code)

    def test_A06_process_exit_before_commit(self):
        self.crash("before_commit",41)
        self.assertEqual(read_current(self.db,self.pub),self.old)
        self.commit()
        self.assertEqual(read_current(self.db,self.pub),self.new)

    def test_A06_process_exit_after_commit(self):
        cache = self.root/"cache"
        cache.write_bytes(self.old[2])
        self.crash("after_commit",42)
        with self.assertRaises(Denied):
            accept(self.db,self.pub,self.old)
        self.assertEqual(recover(self.db,self.pub,cache),self.new)
        self.assertEqual(cache.read_bytes(),self.new[2])

    def test_limit_authority_rollback_NOT_PREVENTED(self):
        # Explicit negative control: a privileged local authority rollback
        # defeats this prototype; never interpret as independent custody.
        self.commit()
        with connect(self.db) as c:
            c.execute("DELETE FROM history WHERE generation=2")
        self.assertEqual(accept(self.db,self.pub,self.old),self.old[2])


if __name__ == "__main__":
    unittest.main()
