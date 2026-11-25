"""SEC143 isolated signed-webhook intake and replay ledger, not an active security gate.

No web server, API token, GitHub App, user approval or check-run publisher.
This source is PR-controlled and must not be used for independent enforcement.
"""
from __future__ import annotations
import hashlib
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from trusted_check_policy import EXPECTED_REPOSITORY, Rejected, verify_webhook

DELIVERY_ID = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
VALID_EVENTS = frozenset({"pull_request", "pull_request_review"})


@dataclass(frozen=True)
class DeliveryReceipt:
    delivery_id: str
    event: str
    repository: str
    installation_id: int
    pr_number: int
    pr_head_sha: str
    body_sha256: str

    def as_dict(self):
        return {
            "delivery_id": self.delivery_id, "event": self.event,
            "repository": self.repository, "installation_id": self.installation_id,
            "pr_number": self.pr_number, "pr_head_sha": self.pr_head_sha,
            "body_sha256": self.body_sha256,
            "status": "WEBHOOK_OBSERVED_ONLY_NOT_AUTHORIZED",
            "check_written": False, "enforcement": "NOT_DEPLOYED",
            "independent_reviewer_verified": False
        }


class DeliveryLedger:
    """Durable SQLite unique ID claim; DB custody remains an external problem."""

    def __init__(self, path):
        self.path = Path(path)
        if not self.path.parent.is_dir():
            raise Rejected("ledger parent must exist")
        with closing(self._connect()) as c:
            try:
                c.execute(
                    "CREATE TABLE IF NOT EXISTS seen ("
                    "delivery_id TEXT PRIMARY KEY, body_sha256 TEXT NOT NULL,"
                    "event TEXT NOT NULL, repository TEXT NOT NULL,"
                    "received_utc TEXT NOT NULL)"
                )
            except sqlite3.Error as exc:
                raise Rejected("ledger setup failed") from exc

    def _connect(self):
        try:
            c = sqlite3.connect(str(self.path), isolation_level=None, timeout=10)
            c.execute("PRAGMA busy_timeout=10000")
            mode = c.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            c.execute("PRAGMA synchronous=FULL")
            if mode.lower() != "wal":
                c.close()
                raise Rejected("WAL unavailable")
            return c
        except sqlite3.Error as exc:
            raise Rejected("ledger unavailable") from exc

    def claim(self, rec: DeliveryReceipt):
        with closing(self._connect()) as c:
            try:
                c.execute("BEGIN IMMEDIATE")
                c.execute(
                    "INSERT INTO seen VALUES (?, ?, ?, ?, ?)",
                    (rec.delivery_id.lower(), rec.body_sha256, rec.event,
                     rec.repository, datetime.now(timezone.utc).isoformat())
                )
                c.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                c.execute("ROLLBACK")
                raise Rejected("duplicate delivery ID (replay)") from exc
            except sqlite3.Error as exc:
                try:
                    c.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise Rejected("ledger write failed closed") from exc


def receive_delivery(*, body: bytes, signature: str, secret: bytes,
                     delivery_id: str, event_name: str, ledger: DeliveryLedger):
    """Verify HMAC before any persistent claim. Does not authorize anything."""
    event = verify_webhook(body, signature, secret)
    if not isinstance(delivery_id, str) or not DELIVERY_ID.fullmatch(delivery_id):
        raise Rejected("invalid X-GitHub-Delivery")
    if event_name not in VALID_EVENTS:
        raise Rejected("unexpected webhook event")
    if not isinstance(ledger, DeliveryLedger):
        raise Rejected("untrusted ledger")
    try:
        repo = event["repository"]["full_name"]
        installation = event["installation"]["id"]
        number = event["number"]
        head = event["pull_request"]["head"]["sha"]
    except (KeyError, TypeError, AttributeError) as exc:
        raise Rejected("incomplete signed event") from exc
    if (repo != EXPECTED_REPOSITORY or
            type(installation) is not int or installation <= 0 or
            type(number) is not int or number <= 0 or
            not isinstance(head, str) or not SHA40.fullmatch(head)):
        raise Rejected("unexpected signed event scope")
    rec = DeliveryReceipt(
        delivery_id.lower(), event_name, repo, installation, number, head,
        hashlib.sha256(body).hexdigest()
    )
    ledger.claim(rec)
    return rec
