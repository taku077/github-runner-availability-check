"""Public synthetic two-witness fixture. No independent custody or real deployment."""
import json
import tempfile
import unittest
from pathlib import Path
from threading import Lock
from test_rca181_signed_generation import (
    Denied, ZERO, openssl, init, advance, connect, make_envelope, verify, read_current,
)
from test_rca182_fresh_anchor import Challenge, issue, verified_advance, sign


def public_der(path):
    r = openssl(["pkey", "-pubin", "-in", str(path), "-outform", "DER"])
    if r.returncode or not r.stdout:
        raise Denied("invalid public key")
    return r.stdout


class DualChallenge:
    """Both pinned signers must freshly attest the same signed state.
    No quorum fallback. The two stores and keys here share one CI owner.
    A snapshot result is not a linearizable authorization/operation lease.
    """
    def __init__(self, wall, monotonic, state_pub, a_pub, b_pub):
        pins = [public_der(p) for p in (state_pub, a_pub, b_pub)]
        if len(set(pins)) != 3:
            raise Denied("keys not distinct")
        self.state_pub, self.a_pub, self.b_pub = state_pub, a_pub, b_pub
        self.a, self.b = Challenge.new(wall, monotonic), Challenge.new(wall, monotonic)
        self.lock = Lock()
        self.used = False

    def check(self, a_response, b_response, candidate, wall, mono):
        with self.lock:
            if self.used:
                raise Denied("consumed")
            self.used = True
        a = self.a.check(a_response, self.a_pub, self.state_pub, candidate, wall, mono)
        b = self.b.check(b_response, self.b_pub, self.state_pub, candidate, wall, mono)
        if a != b:
            raise Denied("disagreement")
        return a


class RCA183DualWitness(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = Path(tmp.name)
        self.sk,self.sp,self.ak,self.ap,self.bk,self.bp = (
            p/x for x in ("state.key","state.pub","a.key","a.pub","b.key","b.pub"))
        for key,pub in ((self.sk,self.sp),(self.ak,self.ap),(self.bk,self.bp)):
            self.assertEqual(openssl(["genpkey","-algorithm","ED25519","-out",str(key)]).returncode,0)
            self.assertEqual(openssl(["pkey","-in",str(key),"-pubout","-out",str(pub)]).returncode,0)
        self.a,self.b = p/"a.sqlite",p/"b.sqlite"
        self.old = make_envelope(self.sk,1,ZERO,b"synthetic generation one")
        self.prev = verify(self.sp,self.old)["digest"]
        self.new = make_envelope(self.sk,2,self.prev,b"synthetic generation two")
        for db in (self.a,self.b):
            init(db)
            advance(db,self.sp,(0,ZERO),self.old)

    def update(self, db, env=None):
        verified_advance(db,self.sp,(1,self.prev),self.new if env is None else env)

    def pair(self):
        c = DualChallenge(100,50,self.sp,self.ap,self.bp)
        return c,issue(self.a,self.sp,self.ak,c.a.nonce,100),issue(self.b,self.sp,self.bk,c.b.nonce,100)

    def both(self):
        self.update(self.a)
        self.update(self.b)

    def rollback(self, db):
        with connect(db) as c:
            c.execute("DELETE FROM history WHERE generation=2")

    def test_agreement_current(self):
        self.both()
        c,a,b = self.pair()
        self.assertEqual(c.check(a,b,self.new,101,51),self.new[2])

    def test_one_side_rollback_denied_either_candidate(self):
        self.both()
        self.rollback(self.b)
        for env in (self.old,self.new):
            c,a,b = self.pair()
            with self.subTest(env=env[2]), self.assertRaises(Denied):
                c.check(a,b,env,101,51)

    def test_same_generation_fork_denied(self):
        fork = make_envelope(self.sk,2,self.prev,b"synthetic fork")
        self.update(self.a)
        self.update(self.b,fork)
        for env in (self.new,fork):
            c,a,b = self.pair()
            with self.subTest(env=env[2]), self.assertRaises(Denied):
                c.check(a,b,env,101,51)

    def test_partial_commit_blocks_then_exact_catchup(self):
        self.update(self.a)
        c,a,b = self.pair()
        with self.assertRaises(Denied):
            c.check(a,b,self.new,101,51)
        # Catch-up uses the exact signed successor already held by A.
        self.update(self.b,read_current(self.a,self.sp))
        c,a,b = self.pair()
        self.assertEqual(c.check(a,b,self.new,101,51),self.new[2])

    def test_missing_either_response(self):
        self.both()
        for side in (0,1):
            c,a,b = self.pair()
            with self.subTest(side=side), self.assertRaises(Denied):
                c.check(None if side==0 else a,None if side==1 else b,self.new,101,51)

    def test_reused_key_pin_denied(self):
        with self.assertRaises(Denied):
            DualChallenge(100,50,self.sp,self.ap,self.ap)
        with self.assertRaises(Denied):
            DualChallenge(100,50,self.sp,self.ap,self.sp)

    def test_one_signer_cannot_substitute_for_other(self):
        self.both()
        c,a,b = self.pair()
        forged = sign(self.ak,json.loads(b[0]))
        with self.assertRaises(Denied):
            c.check(a,forged,self.new,101,51)

    def test_replay_and_expiry(self):
        self.both()
        c,a,b = self.pair()
        self.assertEqual(c.check(a,b,self.new,101,51),self.new[2])
        with self.assertRaises(Denied):
            c.check(a,b,self.new,101,51)
        c2,_,_ = self.pair()
        with self.assertRaises(Denied):
            c2.check(a,b,self.new,101,51)
        c3,a3,b3 = self.pair()
        with self.assertRaises(Denied):
            c3.check(a3,b3,self.new,110,60)

    def test_limit_both_authorities_rollback_NOT_PREVENTED(self):
        self.both()
        self.rollback(self.a)
        self.rollback(self.b)
        c,a,b = self.pair()
        self.assertEqual(c.check(a,b,self.old,101,51),self.old[2])

    def test_limit_snapshot_not_operation_linearization(self):
        # A fresh matching response can predate a concurrent update.
        c,a,b = self.pair()
        self.both()
        self.assertEqual(c.check(a,b,self.old,101,51),self.old[2])
        # This negative control prevents claiming immediate revocation at operation time.
