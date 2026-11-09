#!/usr/bin/env python3
"""Export only synthetic/public EVTX event-reference metadata from checked Hayabusa JSONL.

The returned references are parser-REPORTED, not independently verified.
The Windows verifier joins them against the exact same pinned public EVTX.
No user data, event Details, Computer, IP, SID, path or command line is exported.
"""
import argparse
import hashlib
import json
import pathlib
import sys
from hayabusa_event_receipt import (
    ValidationError, id_value, parse_utc, unique_object, validate_rows,
)

PUBLIC_SAMPLE_SHA256 = "957d0c301baad9e6936683b7aa727d23ca7fb6434eaea786794dae528ecffbe9"


def make_public_index(jsonl_path, source_sha):
    if source_sha != PUBLIC_SAMPLE_SHA256:
        raise ValidationError("source SHA does not identify the approved PUBLIC fixture")
    receipt = validate_rows(jsonl_path, expected_source_sha256=source_sha)
    events = []
    with open(jsonl_path, "rb") as stream:
        for raw in stream:
            if not raw.strip():
                continue
            obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            basename = obj["EvtxFile"].replace("\\", "/").rsplit("/", 1)[-1]
            if basename != "fixture.evtx":
                raise ValidationError("wrong public EVTX reference")
            events.append({
                "record_id": id_value(obj["RecordID"], "RecordID"),
                "event_id": id_value(obj["EventID"], "EventID"),
                "channel": obj["Channel"].strip(),
                "timestamp_utc": parse_utc(obj["Timestamp"]),
            })
    if len(events) != receipt["records"]:
        raise ValidationError("record count changed between reads")
    return {
        "schema": "pcfm-public-independent-evtx-index-v1",
        "status": "HAYABUSA_REPORTED_NOT_SOURCE_VERIFIED",
        "source_basename": "fixture.evtx",
        "source_sha256": source_sha,
        "hayabusa_jsonl_sha256": receipt["jsonl_sha256"],
        "reported_alerts": len(events),
        "event_references": events,
        "contains_private_case_data": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--source-sha256", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)
    try:
        obj = make_public_index(args.jsonl, args.source_sha256)
        dest = pathlib.Path(args.output)
        if dest.exists():
            raise ValidationError("refusing to overwrite index")
        with dest.open("x", encoding="utf-8", newline="\n") as out:
            json.dump(obj, out, sort_keys=True, separators=(",", ":"))
            out.write("\n")
        data = dest.read_bytes()
        print("PCFM_OPS043_PUBLIC_INDEX_CREATED records=%d sha256=%s" %
              (obj["reported_alerts"], hashlib.sha256(data).hexdigest()))
    except (OSError, ValueError) as e:
        print("PCFM_OPS043_INDEX_REJECTED: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
