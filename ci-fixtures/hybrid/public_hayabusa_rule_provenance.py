#!/usr/bin/env python3
"""Public Hayabusa rule provenance verifier (no private case input).

Matches RuleID+RuleFile from a *fixed public EVTX* to the actual .yml files
inside a verified Hayabusa release. A filename or RuleID alone never suffices.
This is a schema/content consistency check, not a security verdict or proof
that the rule's detection logic is correct. No raw alerts or event details
are included in the receipt.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import uuid

from hayabusa_event_receipt import ValidationError, unique_object, validate_rows

SAMPLE_SHA = "957d0c301baad9e6936683b7aa727d23ca7fb6434eaea786794dae528ecffbe9"
RELEASE_SHA = "a4fbdae9b13a5fe0f3b3d98981dd18775f50e5402cf3dee3ba85d4ecd252370e"
ID_LINE = re.compile(r"^id:\s*['\"]?([0-9a-fA-F-]{36})['\"]?(?:\s*(?:#.*)?)?$", re.M)
MAX_RULE_BYTES = 2_000_000
MAX_FILES = 30000
MAX_JSONL = 50_000_000


def parse_rule_uuid(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("non-UTF8 rule file") from exc
    matched = ID_LINE.findall(text)
    if len(matched) != 1:
        return None
    try:
        rule_id = str(uuid.UUID(matched[0]))
    except ValueError:
        return None
    return rule_id


def inventory_rules(root):
    """Reject non-regular and ambiguous rule files; index all explicit rule IDs."""
    root = pathlib.Path(root).resolve(strict=True)
    if not root.is_dir() or root.name != "rules":
        raise ValidationError("expected extracted Hayabusa rules directory")
    files = sorted(root.rglob("*.yml"))
    if not files or len(files) > MAX_FILES:
        raise ValidationError("missing rules or too many rule files")
    known = {}
    summary = []
    for path in files:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValidationError("unsafe rule file")
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if size > MAX_RULE_BYTES:
            raise ValidationError("oversized rule")
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        summary.append([rel, size, sha])
        rule_id = parse_rule_uuid(data)
        if rule_id:
            item = {"rule_id": rule_id, "rule_file": path.name, "relative_path": rel, "sha256": sha}
            known.setdefault(rule_id, []).append(item)
    inventory_sha = hashlib.sha256(json.dumps(summary, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    return known, inventory_sha, len(files)


def verify_rule_provenance(jsonl, root, *, source_sha=SAMPLE_SHA, release_sha=RELEASE_SHA):
    if source_sha != SAMPLE_SHA or release_sha != RELEASE_SHA:
        raise ValidationError("only the pinned public sample and release are allowed")
    receipt = validate_rows(jsonl, expected_source_sha256=source_sha)
    known, inventory_sha, rule_file_count = inventory_rules(root)
    matched = {}
    rows = 0
    with pathlib.Path(jsonl).open("rb") as stream:
        for raw in stream:
            if not raw.strip():
                continue
            obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            rule = obj["RuleID"]
            filename = obj["RuleFile"].replace("\\", "/").rsplit("/", 1)[-1]
            try:
                canonical = str(uuid.UUID(str(rule)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError("invalid rule UUID in timeline") from exc
            candidates = [it for it in known.get(canonical, []) if it["rule_file"] == filename]
            if len(candidates) != 1 or len(known.get(canonical, [])) != 1:
                raise ValidationError("missing/ambiguous/mismatched RuleID-to-file provenance")
            matched[canonical] = candidates[0]
            rows += 1
    if rows != receipt["records"] or not matched:
        raise ValidationError("rule provenance alert count mismatch")
    return {
        "schema": "pcfm-public-ops044-rule-provenance-v1",
        "status": "RELEASE_RULE_UUID_AND_FILE_SHA_MATCHED",
        "sample_sha256": source_sha,
        "hayabusa_release_zip_sha256": release_sha,
        "rule_inventory_sha256": inventory_sha,
        "rule_inventory_file_count": rule_file_count,
        "alerts_linked": rows,
        "matched_rule_count": len(matched),
        "matched_rules": sorted(matched.values(), key=lambda r: r["rule_id"]),
        "rules_semantic_correctness_verified": False,
        "evtx_subsecond_timestamp_verified": False,
        "on_user_pc": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--rules-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = verify_rule_provenance(args.jsonl, args.rules_dir)
        path = pathlib.Path(args.output)
        if path.exists():
            raise ValidationError("no overwriting prior receipts")
        with path.open("x", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        filehash = hashlib.sha256(path.read_bytes()).hexdigest()
        print("PCFM_OPS044_RULE_PROVENANCE_MATCHED alerts=%d rules=%d inventory_files=%d rule_manifest_sha256=%s inventory_sha256=%s" %
              (result["alerts_linked"], result["matched_rule_count"], result["rule_inventory_file_count"],
               filehash, result["rule_inventory_sha256"]))
        print("PCFM_OPS044_RULE_SCOPE=PUBLIC_RULE_CONTENT_ONLY_NO_CORRECTNESS_OR_INCIDENT_ASSERTION")
    except (OSError, ValueError) as exc:
        print("PCFM_OPS044_RULE_REJECTED: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
