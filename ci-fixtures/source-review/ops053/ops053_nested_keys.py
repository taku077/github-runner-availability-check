#!/usr/bin/env python3
"""OPS053: source-pinned, privacy-bounded inventory of nested Windows event ID keys."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import sys
import zipfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "ops052"))
from ops052_inspect import summarize as verify_source, uniq, need, Rejected

SHA256="2ea34cf2d3526e30f9fe004fc4f53f8a04d8e6885e697d77c44102567279ac67"
TOTAL=25208
MAIN_BYTES=48978066
CANON={"eventrecordid":"EventRecordID","recordid":"RecordID","recordnumber":"RecordNumber",
       "sequencenumber":"SequenceNumber","computer":"Computer","channel":"Channel"}
IDS=("EventRecordID","RecordID","RecordNumber","SequenceNumber")
TYPES=("positive_integer","decimal_string","other_or_invalid")

def ident_type(v):
    if type(v) is int and v>0: return "positive_integer"
    if type(v) is str and len(v)<=20 and v.isascii() and v.isdecimal() and int(v)>0:
        return "decimal_string"
    return "other_or_invalid"

def fresh():
    return {label:{"events_with_key":0,"top_level_hits":0,"nested_hits":0,
                   "inside_system_hits":0,
                   "value_type_hits":{k:0 for k in TYPES} if label in IDS else None}
            for label in sorted(set(CANON.values()))}

def inspect_one(obj, counts):
    need(type(obj) is dict,"JSON event must be object")
    stack=[(obj,0,False)]; visited=0; present=set()
    while stack:
        node,depth,under_system=stack.pop()
        visited+=1
        need(visited<=20000 and depth<=20,"nested depth/node budget exceeded")
        if type(node) is dict:
            for key,val in node.items():
                need(type(key) is str,"non-text object key")
                label=CANON.get(key.casefold())
                if label:
                    counts[label]["top_level_hits" if depth==0 else "nested_hits"]+=1
                    if depth and under_system:counts[label]["inside_system_hits"]+=1
                    if label in IDS:counts[label]["value_type_hits"][ident_type(val)]+=1
                    present.add(label)
                if type(val) in (dict,list):
                    stack.append((val,depth+1,under_system or key.casefold()=="system"))
        elif type(node) is list:
            for item in node:
                if type(item) in (dict,list):stack.append((item,depth+1,under_system))
    for label in present:counts[label]["events_with_key"]+=1

def inventory(raw):
    need(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==SHA256,
         "pinned source digest mismatch")
    base=verify_source(raw)
    need(base["json_parse_status"]=="COMPLETE" and base["jsonl_event_objects"]==TOTAL
         and base["member_count"]==2 and base["native_evtx_members"]==0,
         "OPS052 verified source structure changed")
    stats=fresh(); n=0
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        main=[m for m in z.infolist() if not pathlib.PurePosixPath(m.filename).name.startswith("._")
              and "__MACOSX" not in pathlib.PurePosixPath(m.filename).parts]
        need(len(main)==1 and main[0].file_size==MAIN_BYTES
             and pathlib.PurePosixPath(main[0].filename).suffix.lower() in (".json",".jsonl",".ndjson"),
             "main member not pinned")
        content=z.read(main[0]).decode("utf-8-sig")
        need(not content.lstrip().startswith("["),"unexpected JSON array")
        for line in content.splitlines():
            if not line.strip(): continue
            n+=1;need(n<=TOTAL,"unexpected extra event")
            inspect_one(json.loads(line,object_pairs_hook=uniq),stats)
    need(n==TOTAL,"truncated event population")
    return {
        "schema":"pcfm-ops053-nested-key-inventory-v1",
        "case_id":"SDWIN-220705170038",
        "source_sha256":SHA256,
        "source_git_blob_sha1":base["source_git_blob_sha1"],
        "source_zip_size_bytes":len(raw),
        "event_objects":n,
        "whitelist_field_counts_only":stats,
        "record_key_presence_event_counts_sum":sum(stats[x]["events_with_key"] for x in IDS),
        "privacy":"NO_ACTUAL_EVENT_IDS_HOSTNAMES_PAYLOADS_OR_ARBITRARY_PATHS",
        "raw_stringified_xml_and_json_not_searched":True,
        "original_evtx_recordid_linkage":"UNVERIFIED",
        "record_key_presence_not_origination_proof":True,
        "record_key_absence_not_absence_in_original_evtx":True,
        "independent_truth_count":0,
        "source_zip_retained":False,
        "performance_scoring":"BLOCKED",
        "metrics":{x:None for x in ("TP","FP","FN","TN","precision","recall","false_positive_rate")},
        "target_pc_touched":False,"production_deployment_authorized":False
    }

def main():
    a=argparse.ArgumentParser();a.add_argument("--zip",required=True);a.add_argument("--output",required=True)
    args=a.parse_args()
    try:
        need(os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("RUNNER_OS")=="Linux"
             and os.getenv("RUNNER_ENVIRONMENT")=="github-hosted",
             "disposable GitHub-hosted Linux runner required")
        src=pathlib.Path(args.zip);out=pathlib.Path(args.output)
        need(src.is_file() and not src.is_symlink() and src.stat().st_size==1350260,
             "missing/unpinned raw source")
        need(not out.exists() and not out.is_symlink(),"refuse overwrite")
        value=inventory(src.read_bytes())
        with out.open("x",encoding="utf-8",newline="\n") as f:
            json.dump(value,f,sort_keys=True,separators=(",",":"));f.write("\n")
        print("PCFM_OPS053_STRUCTURE_PASS events=25208 record_key_hits="+
              str(value["record_key_presence_event_counts_sum"])+" scoring=BLOCKED")
        print("PCFM_OPS053_RECEIPT_SHA256="+hashlib.sha256(out.read_bytes()).hexdigest())
        return 0
    except (OSError,Rejected,ValueError,zipfile.BadZipFile,UnicodeError):
        print("PCFM_OPS053_REJECTED: failed safe source/structure verification",file=sys.stderr)
        return 1
if __name__=="__main__":raise SystemExit(main())
