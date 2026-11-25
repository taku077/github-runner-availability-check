"""Synthetic-only freshness and verified CAS tests; no external trust anchor."""
import json
import re
import secrets
import tempfile
from pathlib import Path
import unittest
from dataclasses import dataclass
from test_rca181_signed_generation import (
    Denied, canonical, unique, digest, openssl, verify, connect, init,
    advance, make_envelope, read_current, ZERO,
)

DOMAIN = "pcfm-rca182-public-freshness-fixture"
FIELDS = {"domain", "kid", "nonce", "generation", "digest", "metadata_digest", "created", "expires"}
TTL = 10


def sign(key, obj):
    raw = canonical(obj)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "data"
        p.write_bytes(raw)
        r = openssl(["pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(p)])
        if r.returncode or len(r.stdout) != 64:
            raise Denied("signing failed")
        return raw, r.stdout


def issue(db, state_pub, response_key, nonce, now):
    if type(nonce) is not str or not re.fullmatch("[0-9a-f]{64}", nonce):
        raise Denied("nonce")
    env = read_current(db, state_pub)
    meta = verify(state_pub, env)
    return sign(response_key, dict(domain=DOMAIN, kid="response-test-key",
        nonce=nonce, generation=meta["generation"], digest=meta["digest"],
        metadata_digest=digest(env[0]), created=now, expires=now+TTL))


@dataclass
class Challenge:
    nonce: str
    wall: int
    monotonic_deadline: float
    consumed: bool = False

    @classmethod
    def new(cls, wall, monotonic):
        return cls(secrets.token_hex(32), wall, monotonic+TTL)

    def check(self, response, response_pub, state_pub, candidate, now, monotonic):
        if self.consumed:
            raise Denied("already used")
        self.consumed = True
        if not self.wall <= now < self.wall+TTL or monotonic >= self.monotonic_deadline:
            raise Denied("challenge expired")
        try:
            raw, sig = response
            if type(raw) is not bytes or type(sig) is not bytes or not 0 < len(raw) <= 2048 or len(sig) != 64:
                raise Denied("response size/type")
            obj = json.loads(raw, object_pairs_hook=unique)
            if type(obj) is not dict or set(obj) != FIELDS or canonical(obj) != raw:
                raise Denied("response shape")
            if obj["domain"] != DOMAIN or obj["kid"] != "response-test-key" or obj["nonce"] != self.nonce:
                raise Denied("response binding")
            if any(type(obj[k]) is not int for k in ("generation","created","expires")):
                raise Denied("integer types")
            if not self.wall <= obj["created"] <= now < obj["expires"] <= obj["created"]+TTL:
                raise Denied("response time")
            with tempfile.TemporaryDirectory() as d:
                p = Path(d)
                (p/"raw").write_bytes(raw)
                (p/"sig").write_bytes(sig)
                r = openssl(["pkeyutl","-verify","-pubin","-inkey",str(response_pub),
                             "-rawin","-in",str(p/"raw"),"-sigfile",str(p/"sig")])
                if r.returncode:
                    raise Denied("response signature")
            meta = verify(state_pub, candidate)
            if (obj["generation"],obj["digest"],obj["metadata_digest"]) != (
                meta["generation"],meta["digest"],digest(candidate[0])):
                raise Denied("state mismatch")
            return candidate[2]
        except (ValueError, TypeError, OSError) as e:
            raise Denied("invalid response") from e


def verified_advance(db, public, expected, envelope):
    """Validate current signed row under the same write transaction as CAS."""
    obj = verify(public, envelope)
    c = connect(db)
    try:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT generation,digest,meta,sig,state FROM history "
                        "ORDER BY generation DESC LIMIT 1").fetchone()
        if row is None:
            raise Denied("missing authority")
        cur = verify(public, tuple(row[2:]))
        current = (cur["generation"],cur["digest"])
        if current != tuple(row[:2]) or current != expected:
            raise Denied("current row mismatch")
        if obj["generation"] != current[0]+1 or obj["previous"] != current[1]:
            raise Denied("successor mismatch")
        c.execute("INSERT INTO history VALUES (?,?,?,?,?)",
                  (obj["generation"],obj["digest"],*envelope))
        c.commit()
    finally:
        c.close()


class RCA182FreshAnchor(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = Path(tmp.name)
        self.sk,self.sp,self.rk,self.rp = (p/x for x in ("sk","sp","rk","rp"))
        for key,pub in [(self.sk,self.sp),(self.rk,self.rp)]:
            self.assertEqual(openssl(["genpkey","-algorithm","ED25519","-out",str(key)]).returncode,0)
            self.assertEqual(openssl(["pkey","-in",str(key),"-pubout","-out",str(pub)]).returncode,0)
        self.db = p/"fixture.sqlite"
        init(self.db)
        self.old = make_envelope(self.sk,1,ZERO,b"old fixture")
        self.anchor = advance(self.db,self.sp,(0,ZERO),self.old)
        self.new = make_envelope(self.sk,2,self.anchor[1],b"new fixture")
        verified_advance(self.db,self.sp,self.anchor,self.new)

    def fresh(self):
        c = Challenge.new(100,50)
        return c, issue(self.db,self.sp,self.rk,c.nonce,100)

    def test_fresh_valid(self):
        c,r = self.fresh()
        self.assertEqual(c.check(r,self.rp,self.sp,self.new,101,51),self.new[2])

    def test_replay_same_challenge(self):
        c,r = self.fresh()
        c.check(r,self.rp,self.sp,self.new,101,51)
        with self.assertRaises(Denied):
            c.check(r,self.rp,self.sp,self.new,101,51)

    def test_replay_other_challenge(self):
        _,r = self.fresh()
        c = Challenge.new(100,50)
        with self.assertRaises(Denied):
            c.check(r,self.rp,self.sp,self.new,101,51)

    def test_expired_or_clock_rollback(self):
        for now,mono in [(110,51),(101,60),(99,51)]:
            c,r = self.fresh()
            with self.subTest(now=now,mono=mono),self.assertRaises(Denied):
                c.check(r,self.rp,self.sp,self.new,now,mono)

    def test_wrong_signed_fields(self):
        for changes in ({"domain":"other"},{"kid":"other"},{"created":102},
                        {"expires":100},{"expires":111},{"generation":True},
                        {"digest":ZERO},{"metadata_digest":ZERO}):
            c,r = self.fresh()
            obj = json.loads(r[0])
            obj.update(changes)
            with self.subTest(changes=changes),self.assertRaises(Denied):
                c.check(sign(self.rk,obj),self.rp,self.sp,self.new,101,51)

    def test_wrong_response_signing_key(self):
        c,r = self.fresh()
        with self.assertRaises(Denied):
            c.check(sign(self.sk,json.loads(r[0])),self.rp,self.sp,self.new,101,51)

    def test_old_candidate(self):
        c,r = self.fresh()
        with self.assertRaises(Denied):
            c.check(r,self.rp,self.sp,self.old,101,51)

    def test_missing_response(self):
        c,_ = self.fresh()
        with self.assertRaises(Denied):
            c.check(None,self.rp,self.sp,self.new,101,51)

    def test_corrupt_current_rejects_successor(self):
        meta = verify(self.sp,self.new)
        third = make_envelope(self.sk,3,meta["digest"],b"third fixture")
        with connect(self.db) as c:
            c.execute("UPDATE history SET state=? WHERE generation=2",(b"bad",))
        with self.assertRaises(Denied):
            verified_advance(self.db,self.sp,(2,meta["digest"]),third)
        with connect(self.db) as c:
            self.assertEqual(c.execute("SELECT MAX(generation) FROM history").fetchone()[0],2)
        with self.assertRaises(Denied):
            self.fresh()

    def test_limit_fresh_signature_on_rolled_back_authority_NOT_PREVENTED(self):
        # A fresh response proves liveness of its signer, not integrity of its storage.
        with connect(self.db) as c:
            c.execute("DELETE FROM history WHERE generation=2")
        c,r = self.fresh()
        self.assertEqual(c.check(r,self.rp,self.sp,self.old,101,51),self.old[2])
