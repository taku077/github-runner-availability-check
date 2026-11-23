"""RCA171: fixed-scope GET-only GitHub REST evidence; no attribution inference."""
import argparse
from datetime import datetime, timezone
import json
import sys
from urllib.request import Request, urlopen

REPO="taku077/github-runner-availability-check"
BASE="https://api.github.com/repos/"+REPO
MAIN="1b33f359b1079d0c31fc964083991fd875cda304"
CHAIN=(
    "f5202aaad3a2dd5115a8e79f9f2c886b3dd9be4a",
    "e7d5b4c87b7f1213a2d8d6ca811c10073ff70cd4",
    "666995258c6890c357424fd3bb8455b358de2cd6",
    "b7dc89d2efce673af6eeb86c50ac04f457a2e8d2",
    "f98b13ffe4b96e1e9a274cd90041da1992e36043",
    "6d6beffe36469cf5c507c3263025fa33c5d4290b",
)
PROBE="4a8bc15c276ecb87f2543f85e3c4eacbb78701fb"
PATHS=frozenset(["/commits/"+x for x in (*CHAIN,PROBE)]+
                ["/pulls/4","/pulls/5","/pulls/4/reviews",
                 "/pulls/5/reviews","/rulesets/27806733"])
class EvidenceError(ValueError):
    pass

def utc_stamp(value):
    if not isinstance(value,str):
        raise EvidenceError("MISSING_TIME")
    try:
        t=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc:
        raise EvidenceError("INVALID_TIME") from exc
    if t.tzinfo is None or t.utcoffset().total_seconds()!=0:
        raise EvidenceError("NON_UTC_TIME")
    return value

def get_public_json(path, opener=urlopen):
    if path not in PATHS:
        raise EvidenceError("NON_ALLOWLISTED_ENDPOINT")
    request=Request(BASE+path,headers={"Accept":"application/vnd.github+json",
        "User-Agent":"pcfm-rca171-readonly",
        "X-GitHub-Api-Version":"2022-11-28"},method="GET")
    with opener(request, timeout=15) as response:
        if response.geturl()!=BASE+path:
            raise EvidenceError("REDIRECT_NOT_ACCEPTED")
        raw=response.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:
        raise EvidenceError("OVERSIZE_RESPONSE")
    try:
        result=json.loads(raw)
    except ValueError as exc:
        raise EvidenceError("NON_JSON") from exc
    if not isinstance(result,(list,dict)):
        raise EvidenceError("BAD_SHAPE")
    return result

def commit_row(data,sha,parent):
    if not isinstance(data,dict) or data.get("sha")!=sha:
        raise EvidenceError("COMMIT_SHA_MISMATCH")
    parents=data.get("parents")
    if not isinstance(parents,list) or len(parents)!=1 or parents[0].get("sha")!=parent:
        raise EvidenceError("PARENT_CHAIN_MISMATCH")
    obj=data.get("commit")
    if not isinstance(obj,dict):
        raise EvidenceError("NO_GIT_OBJECT")
    stamp=utc_stamp(obj.get("committer",{}).get("date"))
    verification=obj.get("verification")
    if not isinstance(verification,dict) or type(verification.get("verified")) is not bool:
        raise EvidenceError("NO_VERIFICATION_STATUS")
    return {"sha":sha,"parent":parent,"git_object_committer_utc":stamp,
            "git_signature_verified":verification["verified"],
            "signature_reason":str(verification.get("reason","unknown"))[:50]}

def summarize(raw,observed_at_utc):
    utc_stamp(observed_at_utc)
    if not isinstance(raw,dict) or not isinstance(raw.get("commits"),dict):
        raise EvidenceError("INVALID_INPUT")
    commits=raw["commits"]
    if set(commits)!=set((*CHAIN,PROBE)):
        raise EvidenceError("COMMIT_SET_MISMATCH")
    timeline=[commit_row(commits[sha],sha,MAIN if i==0 else CHAIN[i-1])
              for i,sha in enumerate(CHAIN)]
    probe=commit_row(commits[PROBE],PROBE,
           "1961d604fe6a608227c0a54720f08e317ad8c53e")
    prs={}
    for n,head in ((4,PROBE),(5,CHAIN[-1])):
        pr=raw.get("pr"+str(n))
        reviews=raw.get("reviews"+str(n))
        if not isinstance(pr,dict) or pr.get("number")!=n or not isinstance(reviews,list):
            raise EvidenceError("MISSING_PR_OR_REVIEW_DATA")
        if pr.get("base",{}).get("ref")!="main":
            raise EvidenceError("UNEXPECTED_PR_BASE")
        actual=pr.get("head",{}).get("sha")
        prs[str(n)]={"current_head_sha":actual,"case_head_unchanged":actual==head,
                     "draft_at_query":pr.get("draft"),
                     "review_count_at_query":len(reviews)}
    rules=raw.get("ruleset")
    if not isinstance(rules,dict) or rules.get("id")!=27806733:
        raise EvidenceError("RULESET_MISMATCH")
    params=[item.get("parameters",{}) for item in rules.get("rules",[])
            if isinstance(item,dict) and item.get("type")=="pull_request"]
    if len(params)!=1 or type(params[0].get("required_approving_review_count")) is not int:
        raise EvidenceError("RULESET_REVIEWS_UNKNOWN")
    return {
        "schema":"PCFM-RCA171-readonly-provider-v1",
        "observed_at_utc":observed_at_utc,"repository":REPO,
        "pr5_historical_git_chain":timeline,"pr4_probe_git_object":probe,
        "current_pr_metadata":prs,
        "ruleset_required_reviews":params[0]["required_approving_review_count"],
        "limits":{
            "git_object_time_is_provider_push_time":False,
            "signature_or_review_proves_person_identity":False,
            "chatgpt_real_model_input":"NOT_ACQUIRED",
            "native_tool_dispatch":"NOT_ACQUIRED",
            "authenticated_request_id":"NOT_ACQUIRED",
            "authenticated_token_id":"NOT_ACQUIRED",
            "human_consent":"NOT_ATTESTED",
            "third_party_involvement":"UNDETERMINED",
            "ai_vs_human_vs_third_party":"UNDETERMINED",
            "independent_custody":"NOT_ATTESTED",
            "native_non_bypass":"NOT_IMPLEMENTED"},
        "network_scope":"PUBLIC_GITHUB_GET_ONLY"}

def live():
    raw={"commits":{sha:get_public_json("/commits/"+sha)
                    for sha in (*CHAIN,PROBE)},
         "pr4":get_public_json("/pulls/4"),"pr5":get_public_json("/pulls/5"),
         "reviews4":get_public_json("/pulls/4/reviews"),
         "reviews5":get_public_json("/pulls/5/reviews"),
         "ruleset":get_public_json("/rulesets/27806733")}
    return summarize(raw,datetime.now(timezone.utc).isoformat())

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--live",action="store_true")
    args=parser.parse_args()
    if not args.live:
        raise SystemExit(2)
    try:
        result=live()
    except (EvidenceError,OSError,ValueError) as exc:
        print("RCA171_LIVE_NOT_VERIFIED "+type(exc).__name__,file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,separators=(",",":")))
