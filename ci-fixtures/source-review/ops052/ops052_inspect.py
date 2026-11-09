#!/usr/bin/env python3
"""OPS052 inspect one pinned public OTRF ZIP; never publish raw events."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import stat
import sys
import zipfile

EXPECTED_BLOB = "935a63b6ec6a210163a023c5c59a2d61eec87de3"
EXPECTED_BYTES = 1350260
MAX_ARCHIVE_BYTES = 2500000
MAX_MEMBERS = 20
MAX_MEMBER_BYTES = 70000000
MAX_TOTAL_UNCOMPRESSED = 90000000
MAX_LINE_BYTES = 1000000
MAX_EVENTS = 250000
FIELDS = ("EventRecordID","EventRecordId","RecordID","RecordId","RecordNumber",
          "Channel","Computer","EventID","EventId","TimeCreated","UtcTime","SystemTime")

class Rejected(ValueError):
    pass

def need(ok,message):
    if not ok:
        raise Rejected(message)

def git_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def uniq(pairs):
    obj = {}
    for k,v in pairs:
        need(k not in obj,"duplicate JSON key")
        obj[k]=v
    return obj

def summarize(raw,expected_size=EXPECTED_BYTES,expected_blob=EXPECTED_BLOB):
    need(type(raw) is bytes and 0<len(raw)<=MAX_ARCHIVE_BYTES
         and len(raw)==expected_size,"pinned byte count differs")
    need(git_sha(raw)==expected_blob,"pinned Git object SHA differs")
    need(zipfile.is_zipfile(io.BytesIO(raw)),"invalid archive magic")
    kinds=[]
    counts={key:0 for key in FIELDS}
    total_events=0
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        entries=z.infolist()
        need(1<=len(entries)<=MAX_MEMBERS,"unexpected archive entries")
        need(sum(i.file_size for i in entries)<=MAX_TOTAL_UNCOMPRESSED,"uncompressed budget exceeded")
        names=set()
        for i in entries:
            n=i.filename
            p=pathlib.PurePosixPath(n)
            need(n and n not in names and not p.is_absolute() and ".." not in p.parts
                 and "\\" not in n and "\0" not in n and "\r" not in n and "\n" not in n,
                 "unsafe member path")
            need(not stat.S_ISLNK(i.external_attr>>16),"symlink rejected")
            need(not i.is_dir() and 0<i.file_size<=MAX_MEMBER_BYTES,"invalid member size")
            need(i.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),
                 "unsupported ZIP compression")
            names.add(n)
            suffix=p.suffix.lower()
            kind="UNKNOWN"
            if suffix in (".json",".jsonl",".ndjson"):
                kind="JSON_LINES"
                with z.open(i) as stream:
                    ct=0
                    while True:
                        line=stream.readline(MAX_LINE_BYTES+1)
                        if not line:
                            break
                        need(len(line)<=MAX_LINE_BYTES,"JSON line too long")
                        if not line.strip():
                            continue
                        try:
                            obj=json.loads(line.decode("utf-8-sig"),object_pairs_hook=uniq)
                        except (ValueError,UnicodeError) as exc:
                            raise Rejected("invalid JSON Lines data") from exc
                        need(type(obj) is dict,"JSON Lines object expected")
                        ct+=1
                        need(ct+total_events<=MAX_EVENTS,"event count exceeded budget")
                        for key in FIELDS:
                            counts[key]+=int(key in obj)
                    need(ct>0,"empty JSONL")
                total_events+=ct
            elif suffix==".evtx":
                kind="NATIVE_EVTX"
                with z.open(i) as stream:
                    need(stream.read(8)==b"ElfFile\0","native EVTX header mismatch")
            else:
                kind="OTHER_NOT_ANALYZED"
            kinds.append({"type":kind,"compressed_bytes":i.compress_size,
                          "uncompressed_bytes":i.file_size})
        need(z.testzip() is None,"ZIP CRC failed")
    return {"schema":"pcfm-ops052-otrf-acquisition-metadata-v1",
            "source_repo":"OTRF/Security-Datasets",
            "source_commit":"d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
            "case_id":"SDWIN-220705170038",
            "source_git_blob_sha1":expected_blob,"source_git_object_verified":True,
            "source_bytes":len(raw),"source_sha256":hashlib.sha256(raw).hexdigest(),
            "zip_crc_verified":True,"member_count":len(kinds),"members":kinds,
            "jsonl_event_objects":total_events,
            "native_evtx_members":sum(x["type"]=="NATIVE_EVTX" for x in kinds),
            "field_name_presence_counts":counts,
            "independent_ground_truth_event_count":0,
            "attack_event_truth_adjudicated":False,
            "benign_event_truth_adjudicated":False,
            "recordid_mapping_verified":False,
            "performance_scoring_admitted":False,
            "metrics":{k:None for k in ("TP","FP","FN","TN","precision","recall","false_positive_rate")},
            "raw_zip_or_events_uploaded":False,"production_deployment_authorized":False,
            "target_pc_touched":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--zip",required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args()
    try:
        need(os.environ.get("GITHUB_ACTIONS")=="true" and
             os.environ.get("RUNNER_OS")=="Linux" and
             os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted",
             "disposable public Linux runner required")
        source=pathlib.Path(args.zip)
        need(source.is_file() and not source.is_symlink()
             and source.stat().st_size==EXPECTED_BYTES,"pinned source missing or wrong size")
        target=pathlib.Path(args.output)
        need(not target.exists() and not target.is_symlink(),"refusing overwrite")
        result=summarize(source.read_bytes())
        with target.open("x",encoding="utf-8",newline="\n") as f:
            json.dump(result,f,sort_keys=True,separators=(",",":"))
            f.write("\n")
        print("PCFM_OPS052_ARCHIVE_PASS sha256="+result["source_sha256"]+
              " entries="+str(result["member_count"])+
              " jsonl_events="+str(result["jsonl_event_objects"])+
              " scoring=BLOCKED")
        print("PCFM_OPS052_RECEIPT_SHA256="+hashlib.sha256(target.read_bytes()).hexdigest())
        return 0
    except (OSError,Rejected,zipfile.BadZipFile) as exc:
        print("PCFM_OPS052_REJECTED "+str(exc),file=sys.stderr)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
