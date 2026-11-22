"""SEC145 offline webhook lifecycle. PR-controlled source; NOT independent enforcement.

The table records only receipt/observation status. It cannot authorize a
GitHub merge, verify human intent, or emit a privileged check-run.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, verify_webhook

GUID = re.compile(r"^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
RECOVERY_ACTION = "SEC145_SYNTHETIC_RECOVERY_ONLY"


def _now(t):
    if type(t) is not int or t < 0:
        raise Rejected("invalid time")


def _encode(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Worker:
    delivery_id: str
    token: str
    attempt: int
    expires: int


def _receipt(*, body, signature, secret, delivery_id, event):
    payload = verify_webhook(body, signature, secret)  # before any DB write
    if not isinstance(delivery_id, str) or not GUID.fullmatch(delivery_id):
        raise Rejected("invalid delivery GUID")
    if event not in ("pull_request", "pull_request_review"):
        raise Rejected("invalid event type")
    try:
        repo = payload["repository"]["full_name"]
        install = payload["installation"]["id"]
        number = payload["number"]
        head = payload["pull_request"]["head"]["sha"]
    except (KeyError, TypeError, AttributeError) as exc:
        raise Rejected("invalid signed payload") from exc
    if (repo != EXPECTED_REPOSITORY or type(install) is not int or
            install <= 0 or type(number) is not int or number <= 0 or
            not isinstance(head, str) or not SHA.fullmatch(head)):
        raise Rejected("signed payload scope mismatch")
    return (delivery_id.lower(), hashlib.sha256(body).hexdigest(),
            repo, event, install, number, head)


class Lifecycle:
    """Fail-closed state machine with durable SQLite transitions.

    States: RECEIVED -> PROCESSING -> OBSERVED_COMPLETE, or
    PROCESSING -> RECOVERY_HOLD. Re-arm is a synthetic test only.
    """

    def __init__(self, path):
        self.path = Path(path)
        if not self.path.parent.is_dir() or self.path.is_symlink():
            raise Rejected("invalid ledger path")
        with closing(self._open()) as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS lifecycle (
                    delivery_id TEXT PRIMARY KEY,
                    payload_sha256 TEXT NOT NULL,
                    repository TEXT NOT NULL, event TEXT NOT NULL,
                    installation_id INTEGER NOT NULL, number INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'RECEIVED','PROCESSING','OBSERVED_COMPLETE','RECOVERY_HOLD'
                    )),
                    attempt INTEGER NOT NULL DEFAULT 0,
                    worker_token TEXT, expires INTEGER,
                    updated INTEGER NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS recovery_audit (
                    delivery_id TEXT NOT NULL, attempt INTEGER NOT NULL,
                    ticket_hash TEXT NOT NULL UNIQUE, at_time INTEGER NOT NULL,
                    PRIMARY KEY(delivery_id,attempt)
                )
            """)

    def _open(self):
        try:
            c = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
            c.execute("PRAGMA busy_timeout=10000")
            if c.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                c.close()
                raise Rejected("WAL mode missing")
            c.execute("PRAGMA synchronous=FULL")
            return c
        except sqlite3.Error as exc:
            raise Rejected("ledger inaccessible") from exc

    @contextmanager
    def _tx(self):
        with closing(self._open()) as c:
            try:
                c.execute("BEGIN IMMEDIATE")
                yield c
                c.execute("COMMIT")
            except BaseException:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise

    @staticmethod
    def _read(c, guid):
        return c.execute("SELECT * FROM lifecycle WHERE delivery_id=?", (guid,)).fetchone()

    def receive(self, *, body, signature, secret, delivery_id, event, now):
        _now(now)
        p = _receipt(body=body, signature=signature, secret=secret,
                     delivery_id=delivery_id, event=event)
        with self._tx() as c:
            row = self._read(c, p[0])
            if row is None:
                c.execute(
                    "INSERT INTO lifecycle VALUES (?,?,?,?,?,?,?,'RECEIVED',"
                    "0,NULL,NULL,?)", (*p, now)
                )
                status = "NEW_RECEIVED"
            else:
                if tuple(row[:7]) != p:
                    raise Rejected("delivery GUID collision")
                if now < row[11]:
                    raise Rejected("time rollback")
                if row[7] == "PROCESSING" and now >= row[10]:
                    c.execute("UPDATE lifecycle SET state='RECOVERY_HOLD',"
                              "worker_token=NULL,expires=NULL,updated=? "
                              "WHERE delivery_id=?", (now, p[0]))
                    status = "RECOVERY_HOLD"
                else:
                    status = {
                        "RECEIVED": "ALREADY_RECEIVED",
                        "PROCESSING": "IN_PROGRESS",
                        "OBSERVED_COMPLETE": "ALREADY_OBSERVED_COMPLETE",
                        "RECOVERY_HOLD": "RECOVERY_HOLD"
                    }[row[7]]
        return {"status": status, "authorized": False, "check_written": False}

    def start(self, guid, *, now, lease=60):
        _now(now)
        if type(lease) is not int or not 1 <= lease <= 3600:
            raise Rejected("invalid lease")
        with self._tx() as c:
            row = self._read(c, guid)
            if row is None or row[7] != "RECEIVED":
                raise Rejected("observation cannot start")
            if now < row[11]:
                raise Rejected("time rollback")
            attempt = row[8] + 1
            token = secrets.token_hex(24)
            deadline = now + lease
            c.execute(
                "UPDATE lifecycle SET state='PROCESSING',attempt=?,"
                "worker_token=?,expires=?,updated=? WHERE delivery_id=?",
                (attempt, token, deadline, now, guid)
            )
        return Worker(guid, token, attempt, deadline)

    def finish_observation(self, worker, *, now):
        """Only internal intake completion. Not an external API write."""
        _now(now)
        if not isinstance(worker, Worker):
            raise Rejected("invalid worker")
        with self._tx() as c:
            row = self._read(c, worker.delivery_id)
            if row is None or row[7] != "PROCESSING" or row[8] != worker.attempt:
                raise Rejected("stale worker attempt")
            if not hmac.compare_digest(str(row[9]), worker.token):
                raise Rejected("stale worker token")
            if now < row[11] or now >= row[10] or worker.expires != row[10]:
                raise Rejected("worker expired or time rollback")
            c.execute("UPDATE lifecycle SET state='OBSERVED_COMPLETE',"
                      "worker_token=NULL,expires=NULL,updated=? "
                      "WHERE delivery_id=?", (now, worker.delivery_id))
        return {"status": "OBSERVED_COMPLETE_NOT_AUTHORIZED",
                "authorized": False, "check_written": False}

    def hold(self, guid, *, now):
        _now(now)
        with self._tx() as c:
            row = self._read(c, guid)
            if row is None or row[7] != "PROCESSING":
                raise Rejected("not processing")
            if now < row[11]:
                raise Rejected("time rollback")
            if now < row[10]:
                raise Rejected("lease still active")
            c.execute("UPDATE lifecycle SET state='RECOVERY_HOLD',"
                      "worker_token=NULL,expires=NULL,updated=? WHERE delivery_id=?",
                      (now, guid))
        return "RECOVERY_HOLD"

    def status(self, guid):
        with closing(self._open()) as c:
            row = self._read(c, guid)
        if row is None:
            raise Rejected("unknown delivery")
        return {"state": row[7], "attempt": row[8],
                "head": row[6], "check_written": False,
                "authorization": "NONE"}

    def synthetic_rearm(self, ticket, mac, *, fake_key, alleged_live_head, now):
        """A synthetic ticket proves no independent operator identity.

        Host must independently verify operator and GitHub state in real use.
        Neither code nor tests are deployable security enforcement.
        """
        _now(now)
        if type(fake_key) is not bytes or len(fake_key) < 32:
            raise Rejected("weak synthetic recovery key")
        fields = {"action", "delivery_id", "payload_sha256",
                  "head_sha", "attempt", "expires_at"}
        if not isinstance(ticket, dict) or set(ticket) != fields or (
                ticket.get("action") != RECOVERY_ACTION):
            raise Rejected("invalid recovery ticket")
        expected = hmac.new(fake_key, _encode(ticket), hashlib.sha256).hexdigest()
        if not isinstance(mac, str) or not hmac.compare_digest(expected, mac):
            raise Rejected("recovery HMAC mismatch")
        if type(ticket["expires_at"]) is not int or now > ticket["expires_at"]:
            raise Rejected("recovery ticket expired")
        if (not isinstance(alleged_live_head, str) or
                SHA.fullmatch(alleged_live_head) is None or
                alleged_live_head != ticket["head_sha"]):
            raise Rejected("recovery head mismatch")
        with self._tx() as c:
            row = self._read(c, ticket["delivery_id"])
            if (row is None or row[7] != "RECOVERY_HOLD" or
                    row[1] != ticket["payload_sha256"] or
                    row[6] != ticket["head_sha"] or
                    type(ticket["attempt"]) is not int or
                    row[8] != ticket["attempt"] or now < row[11]):
                raise Rejected("recovery is stale")
            try:
                c.execute("INSERT INTO recovery_audit VALUES (?,?,?,?)",
                          (ticket["delivery_id"], ticket["attempt"],
                           hashlib.sha256(_encode(ticket)).hexdigest(), now))
            except sqlite3.IntegrityError as exc:
                raise Rejected("recovery already consumed") from exc
            c.execute("UPDATE lifecycle SET state='RECEIVED',updated=? "
                      "WHERE delivery_id=?", (now, ticket["delivery_id"]))
        return {"status": "SYNTHETIC_REARM_NOT_AUTHORIZED",
                "independent_operator_verified": False,
                "check_written": False}
