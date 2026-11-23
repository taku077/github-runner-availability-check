"""RCA175: real local Git object read backend, not an MCP or OAuth service.

Only a fixed public repository and immutable baseline SHA are available.
No private key, network command after clone, ref mutation, or arbitrary path.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

PUBLIC_REMOTE = "https://github.com/taku077/github-runner-availability-check.git"
REPO = "taku077/github-runner-availability-check"
SNAPSHOT_SHA = "1b33f359b1079d0c31fc964083991fd875cda304"
ALLOWED_PATHS = frozenset({"README.md"})
ALLOWED_OPERATIONS = frozenset({"search", "fetch"})
MAX_FILE_BYTES = 16384
MAX_QUERY_CHARS = 60
MAX_RESULTS = 4

class ReadRejected(ValueError):
    pass

def safe_git_environment(source=None):
    raw = os.environ if source is None else source
    env = {key: raw[key] for key in ("PATH", "HOME", "LANG", "LC_ALL",
                                     "SYSTEMROOT", "TMPDIR", "TMP")
           if key in raw}
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env

def valid_snapshot(sha):
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ReadRejected("INVALID_SNAPSHOT_SHA")
    if sha != SNAPSHOT_SHA:
        raise ReadRejected("SNAPSHOT_NOT_ALLOWLISTED")

def valid_path(path):
    if not isinstance(path, str) or path not in ALLOWED_PATHS:
        raise ReadRejected("PATH_NOT_ALLOWLISTED")
    return path

def valid_query(q):
    if not isinstance(q, str) or not (1 <= len(q) <= MAX_QUERY_CHARS):
        raise ReadRejected("INVALID_QUERY")
    if any(ord(c) < 32 or ord(c) == 127 for c in q):
        raise ReadRejected("CONTROL_IN_QUERY")
    return q.casefold()

def _exec_git(argv, env, limit=MAX_FILE_BYTES + 1024):
    result = subprocess.run(argv, check=False, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode != 0:
        raise ReadRejected("GIT_READ_FAILED")
    if len(result.stdout) > limit:
        raise ReadRejected("GIT_OUTPUT_TOO_LARGE")
    return result.stdout

def _local_git(mirror, args, env):
    # Every caller supplies ONLY fixed Git read commands. No external URL.
    return _exec_git(["git", "-C", str(mirror), *args], env)

def fetch(mirror, sha, path, env):
    valid_snapshot(sha)
    path = valid_path(path)
    if _local_git(mirror, ["cat-file", "-t", sha], env).strip() != b"commit":
        raise ReadRejected("NOT_A_COMMIT")
    spec = sha + ":" + path
    if _local_git(mirror, ["cat-file", "-t", spec], env).strip() != b"blob":
        raise ReadRejected("NOT_A_BLOB")
    try:
        size = int(_local_git(mirror, ["cat-file", "-s", spec], env).strip())
    except ValueError as exc:
        raise ReadRejected("INVALID_BLOB_SIZE") from exc
    if size < 0 or size > MAX_FILE_BYTES:
        raise ReadRejected("BLOB_SIZE_DENIED")
    raw = _local_git(mirror, ["cat-file", "blob", spec], env)
    if len(raw) != size:
        raise ReadRejected("BLOB_SIZE_MISMATCH")
    try:
        contents = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ReadRejected("BINARY_BLOB_DENIED") from exc
    blob_sha = _local_git(mirror, ["rev-parse", "--verify", spec], env).strip().decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{40}", blob_sha):
        raise ReadRejected("INVALID_GIT_BLOB_SHA")
    return {
        "id": sha + ":" + path,
        "title": path,
        "url": "https://github.com/" + REPO + "/blob/" + sha + "/" + path,
        "text": contents,
        "git_blob_sha": blob_sha,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": size,
        "source": "LOCAL_PINNED_PUBLIC_GIT_MIRROR",
    }

def search(mirror, sha, query, env):
    valid_snapshot(sha)
    term = valid_query(query)
    found = []
    for path in sorted(ALLOWED_PATHS):
        document = fetch(mirror, sha, path, env)
        for number, line in enumerate(document["text"].splitlines(), start=1):
            if term in line.casefold():
                found.append({
                    "id": document["id"],
                    "title": document["title"],
                    "url": document["url"],
                    "snippet": line[:200],
                    "line": number,
                    "sha256": document["sha256"],
                })
                if len(found) >= MAX_RESULTS:
                    return found
    return found

def dispatch(mirror, sha, operation, params, env):
    if operation not in ALLOWED_OPERATIONS:
        raise ReadRejected("OPERATION_DENIED_NO_EXECUTION")
    if not isinstance(params, dict):
        raise ReadRejected("BAD_INPUT")
    if operation == "fetch":
        if set(params) != {"path"}:
            raise ReadRejected("BAD_FETCH_SCHEMA")
        return fetch(mirror, sha, params["path"], env)
    if set(params) != {"query"}:
        raise ReadRejected("BAD_SEARCH_SCHEMA")
    return search(mirror, sha, params["query"], env)

def live_public():
    env = safe_git_environment()
    with TemporaryDirectory(prefix="pcfm-rca175-readonly-") as temporary:
        mirror = Path(temporary) / "public-mirror.git"
        # Clone affects only the temporary local mirror. HTTPS remote is fixed.
        _exec_git(["git", "-c", "credential.helper=", "-c", "protocol.allow=never",
                   "-c", "protocol.https.allow=always",
                   "clone", "--mirror", "--", PUBLIC_REMOTE, str(mirror)],
                  env, limit=65536)
        if _local_git(mirror, ["cat-file", "-t", SNAPSHOT_SHA], env).strip() != b"commit":
            raise ReadRejected("BASELINE_MISSING")
        doc = dispatch(mirror, SNAPSHOT_SHA, "fetch", {"path": "README.md"}, env)
        matches = dispatch(mirror, SNAPSHOT_SHA, "search", {"query": "runner"}, env)
        if not matches or matches[0]["sha256"] != doc["sha256"]:
            raise ReadRejected("SEARCH_FETCH_INCONSISTENT")
        return {
            "schema": "PCFM-RCA175-local-public-read-backend-v1",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "git_source": REPO,
            "snapshot_sha": SNAPSHOT_SHA,
            "read_operations": sorted(ALLOWED_OPERATIONS),
            "fetch_path": doc["title"],
            "fetch_sha256": doc["sha256"],
            "fetch_git_blob_sha": doc["git_blob_sha"],
            "fetch_bytes": doc["size_bytes"],
            "search_matches": len(matches),
            "search_same_document_hash": True,
            "git_remote_write_attempts": 0,
            "private_git_credentials_used": False,
            "private_repo_read": "NOT_ATTEMPTED",
            "oauth_authentication": "NOT_IMPLEMENTED",
            "streamable_http_mcp": "NOT_IMPLEMENTED",
            "chatgpt_connector_test": "NOT_PERFORMED",
            "independent_writer": "NOT_DEPLOYED",
            "native_write_denial": "NOT_ESTABLISHED",
            "source_attribution": "UNDETERMINED",
        }

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--live-public", action="store_true", required=True)
    parser.parse_args(argv)
    try:
        report = live_public()
    except (ReadRejected, OSError, subprocess.TimeoutExpired) as exc:
        print("RCA175_LIVE_NOT_VERIFIED " + type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
