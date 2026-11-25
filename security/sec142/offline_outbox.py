"""SEC146 offline transactional outbox: NEVER emits or authorizes a GitHub check.

All states and remote observations are synthetic or caller-supplied. This is
PR-controlled source, not independently administered App code. In particular,
'UNKNOWN_REMOTE_RESULT' MUST NOT be automatically retried.
"""
from __future__ import annotations

import hashlib
import json
import re

from delivery_lifecycle import Lifecycle
from trusted_check_policy import Rejected

SHA40 = re.compile(r"^[0-9a-f]{40}$")
OP = "SEC146_LOCAL_UNTRUSTED_CHECK_INTENT"
STATES = frozenset({
    "PREPARED_LOCAL_ONLY", "UNKNOWN_REMOTE_RESULT",
    "RECONCILIATION_HOLD", "CANCELLED_WITHOUT_SEND",
})


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sha(value):
    return type(value) is str and SHA40.fullmatch(value) is not None


class OfflineOutbox:
    """Same SQLite transaction domain as Lifecycle; no remote API client."""

    def __init__(self, lifecycle: Lifecycle):
        if not isinstance(lifecycle, Lifecycle):
            raise Rejected("expected SEC145 lifecycle store")
        self.lifecycle = lifecycle
        with lifecycle._tx() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS outbox_intents (
                    intent_id TEXT PRIMARY KEY,
                    delivery_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'PREPARED_LOCAL_ONLY','UNKNOWN_REMOTE_RESULT',
                        'RECONCILIATION_HOLD','CANCELLED_WITHOUT_SEND'
                    )),
                    created_tick INTEGER NOT NULL,
                    observation_digest TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS outbox_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_id TEXT NOT NULL, transition TEXT NOT NULL,
                    at_tick INTEGER NOT NULL
                )
            """)

    @staticmethod
    def _receipt(row):
        return {"intent_id": row[0], "delivery_id": row[1],
                "attempt": row[2], "head_sha": row[3],
                "status": row[5], "check_written": False,
                "real_github_api_called": False,
                "independent_provenance": "NOT_ATTESTED",
                "authorization": "NONE"}

    @staticmethod
    def _get(c, intent_id):
        return c.execute("SELECT * FROM outbox_intents WHERE intent_id=?",
                         (intent_id,)).fetchone()

    def prepare(self, delivery_id, *, asserted_head_sha, tick):
        """Prepare a local-only intent bound to the observed attempt/HEAD.

        The caller's head is NOT an independent live GitHub API readback.
        """
        if not _sha(asserted_head_sha) or type(tick) is not int or tick < 0:
            raise Rejected("invalid intent SHA or tick")
        with self.lifecycle._tx() as c:
            row = self.lifecycle._read(c, delivery_id)
            if row is None or row[7] != "OBSERVED_COMPLETE" or row[8] <= 0:
                raise Rejected("observation not completed")
            if row[6] != asserted_head_sha:
                raise Rejected("stale candidate head SHA")
            if tick < row[11]:
                raise Rejected("outbox clock rollback")
            intent_id = hashlib.sha256(_canon(
                [delivery_id, row[8], row[6], OP]
            )).hexdigest()
            old = self._get(c, intent_id)
            if old is None:
                c.execute(
                    "INSERT INTO outbox_intents VALUES "
                    "(?,?,?,?,?,'PREPARED_LOCAL_ONLY',?,NULL)",
                    (intent_id, delivery_id, row[8], row[6], OP, tick)
                )
                c.execute("INSERT INTO outbox_events "
                          "(intent_id,transition,at_tick) VALUES (?,?,?)",
                          (intent_id, "PREPARED_LOCAL_ONLY", tick))
            else:
                if (old[1], old[2], old[3], old[4]) != (
                    delivery_id, row[8], row[6], OP
                ):
                    raise Rejected("intent identity collision")
            current = self._get(c, intent_id)
        return self._receipt(current)

    def status(self, intent_id):
        with self.lifecycle._tx() as c:
            row = self._get(c, intent_id)
        if row is None:
            raise Rejected("unknown outbox intent")
        return self._receipt(row)

    def _move(self, intent_id, expected, target, tick, digest=None):
        if type(tick) is not int or tick < 0 or target not in STATES:
            raise Rejected("invalid transition")
        with self.lifecycle._tx() as c:
            row = self._get(c, intent_id)
            last_tick = c.execute(
                "SELECT MAX(at_tick) FROM outbox_events WHERE intent_id=?",
                (intent_id,)
            ).fetchone()[0]
            if (row is None or row[5] != expected or last_tick is None or
                    tick < last_tick):
                raise Rejected("outbox transition denied")
            c.execute(
                "UPDATE outbox_intents SET state=?, observation_digest=? "
                "WHERE intent_id=? AND state=?",
                (target, digest, intent_id, expected)
            )
            c.execute("INSERT INTO outbox_events "
                      "(intent_id,transition,at_tick) VALUES (?,?,?)",
                      (intent_id, target, tick))
            fresh = self._get(c, intent_id)
        return self._receipt(fresh)

    def mark_uncertain(self, intent_id, *, tick):
        """Models a lost network response; it performs NO network operation."""
        return self._move(intent_id, "PREPARED_LOCAL_ONLY",
                          "UNKNOWN_REMOTE_RESULT", tick)

    def cancel_before_sending(self, intent_id, *, tick):
        return self._move(intent_id, "PREPARED_LOCAL_ONLY",
                          "CANCELLED_WITHOUT_SEND", tick)

    def record_untrusted_remote_observation(self, intent_id, *, tick,
                                            remote_sample):
        """Record untrusted API-like JSON for manual reconciliation only.

        A legitimate trusted host would re-fetch the exact head, source App,
        check external_id and reviewer identity out of band. Not implemented.
        """
        if not isinstance(remote_sample, dict) or set(remote_sample) != {
            "head_sha", "app_id", "external_id", "check_id", "conclusion"
        }:
            raise Rejected("incomplete remote observation")
        if (not _sha(remote_sample["head_sha"]) or
                type(remote_sample["app_id"]) is not int or
                remote_sample["app_id"] <= 0 or
                type(remote_sample["check_id"]) is not int or
                remote_sample["check_id"] <= 0 or
                not isinstance(remote_sample["external_id"], str) or
                not remote_sample["external_id"].strip() or
                remote_sample["conclusion"] not in
                ("neutral", "action_required", None)):
            raise Rejected("remote observation is not admissible")
        with self.lifecycle._tx() as c:
            row = self._get(c, intent_id)
            if row is None or row[5] != "UNKNOWN_REMOTE_RESULT":
                raise Rejected("remote observation out of sequence")
            if remote_sample["head_sha"] != row[3] or (
                    remote_sample["external_id"] != intent_id):
                raise Rejected("remote check belongs to a different intent/head")
            if tick < row[6]:
                raise Rejected("outbox clock rollback")
        # This digest is an observation trace, NOT trusted App provenance.
        digest = hashlib.sha256(_canon(remote_sample)).hexdigest()
        return self._move(intent_id, "UNKNOWN_REMOTE_RESULT",
                          "RECONCILIATION_HOLD", tick, digest)
