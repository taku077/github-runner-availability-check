"""SEC144 offline SQLite custody snapshot and fail-closed restore preflight.

PR-controlled synthetic prototype only. NEVER an independent immutable proof,
GitHub App, operator attestation, real restore action, or merge authorization.
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
from typing import Any

from trusted_check_policy import Rejected

SCHEMA = "pcfm-sec144-offline-snapshot-v1"
ROWS_SQL = ("SELECT delivery_id, body_sha256, event, repository, "
            "received_utc FROM seen ORDER BY delivery_id")


def _key(secret: bytes) -> None:
    if type(secret) is not bytes or len(secret) < 16:
        raise Rejected("invalid external verification key")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _open_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file() or path.is_symlink():
        raise Rejected("missing or unsafe database path")
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro",
                               uri=True, timeout=10)
        conn.execute("PRAGMA query_only=ON")
        return conn
    except sqlite3.Error as exc:
        raise Rejected("database not readable") from exc


def _row_evidence(conn: sqlite3.Connection) -> tuple[int, str]:
    try:
        result = conn.execute("PRAGMA integrity_check").fetchall()
        if result != [("ok",)]:
            raise Rejected("SQLite integrity verification failed")
        digest = hashlib.sha256()
        count = 0
        for row in conn.execute(ROWS_SQL):
            item = _canonical(row)
            digest.update(len(item).to_bytes(4, "big"))
            digest.update(item)
            count += 1
        return count, digest.hexdigest()
    except sqlite3.Error as exc:
        raise Rejected("ledger schema or integrity failure") from exc


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            digest.update(block)
    return digest.hexdigest()


def _external_receipt(manifest: dict) -> dict:
    return {
        "schema": SCHEMA, "delivery_count": manifest["delivery_count"],
        "snapshot_sha256": manifest["snapshot_sha256"],
        "rows_sha256": manifest["rows_sha256"],
        "result": "OFFLINE_SNAPSHOT_VERIFIED_NOT_INDEPENDENT",
        "restored": False, "check_written": False,
        "independent_custody": "NOT_ATTESTED",
        "live_merge_enforcement": "NOT_DEPLOYED",
    }


def export_snapshot(*, live_db: Path, snapshot_db: Path,
                    manifest_file: Path, external_key: bytes) -> dict:
    """Consistent SQLite backup plus key-dependent manifest; never overwrite.

    The caller must keep the key outside PR-controlled source and must
    independently secure manifest and snapshot files. In this demo the keys
    are synthetic and the files are throwaway.
    """
    _key(external_key)
    live_db = Path(live_db)
    snapshot_db = Path(snapshot_db)
    manifest_file = Path(manifest_file)
    if (snapshot_db == live_db or manifest_file == live_db or
            snapshot_db == manifest_file or
            snapshot_db.exists() or manifest_file.exists() or
            not snapshot_db.parent.is_dir() or
            not manifest_file.parent.is_dir()):
        raise Rejected("unsafe or existing snapshot path")
    with closing(_open_read_only(live_db)) as source:
        _row_evidence(source)
        # Exclusive creation prevents silently replacing an existing evidence
        # file. A crash leaves an incomplete destination: never auto-delete it.
        try:
            fd = os.open(snapshot_db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except OSError as exc:
            raise Rejected("snapshot path creation failed") from exc
        try:
            with closing(sqlite3.connect(str(snapshot_db))) as target:
                source.backup(target)
        except sqlite3.Error as exc:
            raise Rejected("SQLite online backup failed; quarantine partial file") from exc
    with closing(_open_read_only(snapshot_db)) as backup:
        count, rows_sha = _row_evidence(backup)
    manifest = {
        "schema": SCHEMA, "created_utc": datetime.now(timezone.utc).isoformat(),
        "delivery_count": count, "rows_sha256": rows_sha,
        "snapshot_sha256": _file_hash(snapshot_db),
        "authorization": "NONE", "backup_is_independent": False
    }
    mac = hmac.new(external_key, _canonical(manifest), hashlib.sha256).hexdigest()
    envelope = {"manifest": manifest, "hmac_sha256": mac}
    try:
        with manifest_file.open("x", encoding="utf-8") as out:
            out.write(_canonical(envelope).decode("ascii") + "\n")
            out.flush()
            os.fsync(out.fileno())
    except OSError as exc:
        raise Rejected("manifest write failed; quarantine partial files") from exc
    return _external_receipt(manifest)


def verify_snapshot(*, snapshot_db: Path, manifest_file: Path,
                    external_key: bytes, current_db: Path | None = None) -> dict:
    """Restore preflight only. NEVER copy a snapshot onto an existing ledger."""
    _key(external_key)
    snapshot_db = Path(snapshot_db)
    manifest_file = Path(manifest_file)
    if (not manifest_file.is_file() or manifest_file.is_symlink() or
            manifest_file.stat().st_size > 4096):
        raise Rejected("missing or unsafe manifest")
    try:
        envelope = json.loads(manifest_file.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or set(envelope) != {"manifest", "hmac_sha256"}:
            raise Rejected("invalid manifest envelope")
        manifest = envelope["manifest"]
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
            raise Rejected("wrong snapshot manifest schema")
        if set(manifest) != {"schema", "created_utc", "delivery_count",
                             "rows_sha256", "snapshot_sha256", "authorization",
                             "backup_is_independent"}:
            raise Rejected("invalid snapshot manifest fields")
        provided = envelope["hmac_sha256"]
        if type(provided) is not str or len(provided) != 64:
            raise Rejected("invalid manifest HMAC")
        expected = hmac.new(external_key, _canonical(manifest),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, provided):
            raise Rejected("manifest HMAC mismatch")
        if (manifest["authorization"] != "NONE" or
                manifest["backup_is_independent"] is not False):
            raise Rejected("manifest claims unsupported authorization")
        if (type(manifest["delivery_count"]) is not int or
                manifest["delivery_count"] < 0):
            raise Rejected("invalid recorded row count")
        if (not isinstance(manifest["snapshot_sha256"], str) or
                not isinstance(manifest["rows_sha256"], str)):
            raise Rejected("invalid recorded SHA values")
    except (ValueError, UnicodeError, OSError, TypeError, KeyError) as exc:
        if isinstance(exc, Rejected):
            raise
        raise Rejected("invalid manifest encoding") from exc
    if not snapshot_db.is_file() or snapshot_db.is_symlink():
        raise Rejected("missing or unsafe snapshot")
    if _file_hash(snapshot_db) != manifest["snapshot_sha256"]:
        raise Rejected("snapshot file SHA mismatch")
    with closing(_open_read_only(snapshot_db)) as database:
        count, rows_sha = _row_evidence(database)
    if (count != manifest["delivery_count"] or
            rows_sha != manifest["rows_sha256"]):
        raise Rejected("snapshot row evidence mismatch")
    if current_db is not None:
        with closing(_open_read_only(Path(current_db))) as live:
            live_count, live_sha = _row_evidence(live)
        # This is a strict exact-match preflight. A live ledger with additional
        # events is refused rather than automatically overwritten.
        if live_count != count or live_sha != rows_sha:
            raise Rejected("live ledger differs; manual recovery review required")
    return _external_receipt(manifest)
