"""SEC146 combined lifecycle/outbox snapshot and restore PRE-FLIGHT ONLY.

Source and fixtures are PR-controlled. This does not independently attest
origin, prevent modification of live records, restore a database, or publish
GitHub checks. The verification key must live outside this source tree.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from trusted_check_policy import Rejected

SCHEMA = "pcfm-sec146-lifecycle-outbox-custody-v1"
TABLES = {
    "lifecycle": "SELECT delivery_id,payload_sha256,repository,event,"
                 "installation_id,number,head_sha,state,attempt,"
                 "worker_token,expires,updated FROM lifecycle ORDER BY delivery_id",
    "recovery_audit": "SELECT delivery_id,attempt,ticket_hash,at_time "
                      "FROM recovery_audit ORDER BY delivery_id,attempt",
    "outbox_intents": "SELECT intent_id,delivery_id,attempt,head_sha,operation,"
                      "state,created_tick,observation_digest "
                      "FROM outbox_intents ORDER BY intent_id",
    "outbox_events": "SELECT id,intent_id,transition,at_tick "
                     "FROM outbox_events ORDER BY id",
}


def _key(key):
    if type(key) is not bytes or len(key) < 32:
        raise Rejected("invalid external snapshot key")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _read_only(db):
    path = Path(db)
    if not path.is_file() or path.is_symlink():
        raise Rejected("missing or unsafe source database")
    try:
        conn = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro",
            uri=True, timeout=10, isolation_level=None
        )
        conn.execute("PRAGMA query_only=ON")
        return conn
    except sqlite3.Error as exc:
        raise Rejected("database unavailable") from exc


def _digest_rows(conn):
    try:
        if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise Rejected("database integrity failure")
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if not set(TABLES).issubset(names):
            raise Rejected("missing required SEC145/146 custody tables")
        result = {}
        for name, sql in TABLES.items():
            digest = hashlib.sha256()
            rows = 0
            for row in conn.execute(sql):
                data = _canon(row)
                digest.update(len(data).to_bytes(4, "big"))
                digest.update(data)
                rows += 1
            result[name] = {"count": rows, "sha256": digest.hexdigest()}
        return result
    except sqlite3.Error as exc:
        raise Rejected("custody tables cannot be read") from exc


def _hashfile(path):
    h = hashlib.sha256()
    try:
        with Path(path).open("rb") as fd:
            while True:
                chunk = fd.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        raise Rejected("snapshot read failed") from exc
    return h.hexdigest()


def _receipt(manifest):
    return {
        "status": "SEC146_SNAPSHOT_PREFLIGHT_ONLY",
        "table_counts": {name: manifest["tables"][name]["count"]
                         for name in sorted(TABLES)},
        "snapshot_sha256": manifest["snapshot_sha256"],
        "restored": False, "check_written": False,
        "external_custody_attested": False,
        "independent_enforcement": "NOT_DEPLOYED",
    }


def export_custody_snapshot(*, source_db, snapshot_db, manifest_file, test_key):
    """SQLite backup includes lifecycle, recovery audit and local-only outbox.

    No overwrite; partial interrupted files are quarantine candidates.
    A separate immutable custodian and an independently authenticated key are
    necessary before making evidentiary or production recovery claims.
    """
    _key(test_key)
    source = Path(source_db)
    target = Path(snapshot_db)
    manifest_path = Path(manifest_file)
    if (source.resolve() in (target.resolve(), manifest_path.resolve()) or
            target.resolve() == manifest_path.resolve() or target.exists() or
            manifest_path.exists() or not target.parent.is_dir() or
            not manifest_path.parent.is_dir()):
        raise Rejected("unsafe or pre-existing snapshot/manifest path")
    with closing(_read_only(source)) as original:
        _digest_rows(original)  # enforce schema before starting output
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        except OSError as exc:
            raise Rejected("snapshot exclusive creation failed") from exc
        try:
            with closing(sqlite3.connect(str(target))) as backup:
                original.backup(backup)
        except sqlite3.Error as exc:
            raise Rejected("SQLite backup failed; quarantine partial file") from exc
    with closing(_read_only(target)) as stored:
        evidence = _digest_rows(stored)
    manifest = {
        "schema": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "snapshot_sha256": _hashfile(target),
        "tables": evidence,
        "authorized": False,
        "independent_custody": False,
    }
    signature = hmac.new(test_key, _canon(manifest), hashlib.sha256).hexdigest()
    envelope = {"manifest": manifest, "hmac_sha256": signature}
    try:
        with manifest_path.open("x", encoding="utf-8") as f:
            f.write(_canon(envelope).decode("ascii") + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        raise Rejected("manifest write failed; quarantine partial files") from exc
    return _receipt(manifest)


def verify_custody_snapshot(*, snapshot_db, manifest_file, test_key,
                            current_db=None):
    """Verify-only. Current DB changes strictly reject stale restore candidates."""
    _key(test_key)
    manifest_path = Path(manifest_file)
    if (not manifest_path.is_file() or manifest_path.is_symlink() or
            manifest_path.stat().st_size > 8192):
        raise Rejected("missing or unsafe custody manifest")
    try:
        envelope = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError) as exc:
        raise Rejected("invalid custody manifest encoding") from exc
    if (type(envelope) is not dict or
            set(envelope) != {"manifest", "hmac_sha256"} or
            type(envelope["manifest"]) is not dict):
        raise Rejected("unexpected custody manifest envelope")
    manifest = envelope["manifest"]
    if (set(manifest) != {"schema", "created_utc", "snapshot_sha256",
                         "tables", "authorized", "independent_custody"} or
            manifest.get("schema") != SCHEMA):
        raise Rejected("unexpected custody manifest schema")
    sig = envelope["hmac_sha256"]
    if (not isinstance(sig, str) or len(sig) != 64 or
            not hmac.compare_digest(
                hmac.new(test_key, _canon(manifest), hashlib.sha256).hexdigest(),
                sig)):
        raise Rejected("custody manifest HMAC mismatch")
    if (manifest["authorized"] is not False or
            manifest["independent_custody"] is not False or
            type(manifest["tables"]) is not dict or
            set(manifest["tables"]) != set(TABLES)):
        raise Rejected("custody authorization or tables mismatch")
    for name in TABLES:
        info = manifest["tables"][name]
        if (type(info) is not dict or set(info) != {"count", "sha256"} or
                type(info["count"]) is not int or info["count"] < 0 or
                type(info["sha256"]) is not str or len(info["sha256"]) != 64):
            raise Rejected("invalid custody counts/digests")
    snapshot = Path(snapshot_db)
    if not snapshot.is_file() or snapshot.is_symlink():
        raise Rejected("missing or unsafe custody snapshot")
    if _hashfile(snapshot) != manifest["snapshot_sha256"]:
        raise Rejected("custody snapshot SHA mismatch")
    with closing(_read_only(snapshot)) as backup:
        actual = _digest_rows(backup)
    if actual != manifest["tables"]:
        raise Rejected("custody rows/count mismatch")
    if current_db is not None:
        with closing(_read_only(current_db)) as live:
            live_digest = _digest_rows(live)
        if live_digest != actual:
            raise Rejected("current ledger differs; manual investigation required")
    return _receipt(manifest)
