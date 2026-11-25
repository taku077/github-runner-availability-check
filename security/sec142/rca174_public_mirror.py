"""RCA174: ephemeral verified public Git mirror, read-only remote transport.

Never handles private repositories or deploy keys. No public CI secrets.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

PUBLIC_REMOTE="https://github.com/taku077/github-runner-availability-check.git"
EXPECTED_MAIN="1b33f359b1079d0c31fc964083991fd875cda304"
MAX_BUNDLE_BYTES=48*1024*1024

class MirrorError(ValueError):
    pass

def git_environment(source=None):
    inherited=dict(os.environ if source is None else source)
    excluded={"GITHUB_TOKEN","GH_TOKEN","GIT_ASKPASS","SSH_ASKPASS",
              "GIT_SSH_COMMAND","GIT_SSH","GIT_CONFIG_COUNT"}
    for key in tuple(inherited):
        if key in excluded or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            inherited.pop(key,None)
    inherited.update({"GIT_TERMINAL_PROMPT":"0","GIT_CONFIG_NOSYSTEM":"1",
                      "GIT_CONFIG_GLOBAL":os.devnull,"GIT_LFS_SKIP_SMUDGE":"1"})
    return inherited

def command_argv(mirror,bundle):
    mirror=str(mirror)
    bundle=str(bundle)
    return (
       ["git","-c","credential.helper=","clone","--mirror","--",PUBLIC_REMOTE,mirror],
       ["git","-C",mirror,"fsck","--full","--no-reflogs"],
       ["git","-C",mirror,"rev-parse","--verify","refs/heads/main"],
       ["git","-C",mirror,"for-each-ref","--format=%(refname):%(objectname)"],
       ["git","-C",mirror,"bundle","create",bundle,"--all"],
       ["git","-C",mirror,"bundle","verify",bundle],
    )

def _run(argv,env,timeout=55):
    return subprocess.run(argv,env=env,capture_output=True,text=True,
                          check=True,timeout=timeout).stdout.strip()

def sha256_file(path):
    digest=hashlib.sha256()
    total=0
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            total+=len(chunk)
            if total>MAX_BUNDLE_BYTES:
                raise MirrorError("PUBLIC_BUNDLE_LIMIT_EXCEEDED")
            digest.update(chunk)
    return digest.hexdigest(),total

def live_public():
    env=git_environment()
    with TemporaryDirectory(prefix="pcfm-rca174-readonly-") as temporary:
        mirror=Path(temporary)/"public_mirror.git"
        bundle=Path(temporary)/"public_ref_bundle.bundle"
        cmds=command_argv(mirror,bundle)
        _run(cmds[0],env)
        _run(cmds[1],env)
        main=_run(cmds[2],env)
        refs=_run(cmds[3],env).splitlines()
        if len(main)!=40 or any(c not in "0123456789abcdef" for c in main):
            raise MirrorError("INVALID_MAIN_SHA")
        if not any(ref.startswith("refs/heads/main:"+main) for ref in refs):
            raise MirrorError("REF_INVENTORY_MISSING_MAIN")
        _run(cmds[4],env)
        _run(cmds[5],env)
        digest,size=sha256_file(bundle)
        if size==0:
            raise MirrorError("EMPTY_BUNDLE")
        if main!=EXPECTED_MAIN:
            raise MirrorError("PUBLIC_MAIN_SHA_DRIFT")
        return {
          "schema":"PCFM-RCA174-public-mirror-readonly-v1",
          "observed_at_utc":datetime.now(timezone.utc).isoformat(),
          "repo":"taku077/github-runner-availability-check",
          "transport":"PUBLIC_GIT_HTTPS_NO_CREDENTIALS",
          "mirror_fsck":"PASS","bundle_verify":"PASS",
          "bundle_size_bytes":size,"ephemeral_bundle_sha256":digest,
          "refs_count":len(refs),"observed_main_sha":main,
          "baseline_main_sha":EXPECTED_MAIN,
          "private_repo_touched":False,
          "private_deploy_key_in_use":False,
          "private_mirror_readback":"NOT_TESTED",
          "durable_backup":"NOT_CREATED_EPHEMERAL_ONLY",
          "chatgpt_private_read_replacement":"NOT_DEPLOYED",
          "native_write_bypass":"NOT_BLOCKED",
          "origin_attribution":"UNDETERMINED"}

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--live-public",action="store_true",required=True)
    parser.parse_args(argv)
    try:
        result=live_public()
    except (MirrorError,OSError,subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print("RCA174_LIVE_MIRROR_NOT_VERIFIED "+type(exc).__name__,file=sys.stderr)
        return 2
    print(json.dumps(result,sort_keys=True,ensure_ascii=False,separators=(",",":")))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
