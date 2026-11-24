"""RCA179 public-only real subprocess restart and pinned state integrity trial.
The parent holds a trusted test digest across service restarts. Not external
custody, persistent monotonic storage, production OAuth or native write denial.
"""
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from datetime import datetime, timezone

import rca175_mirror_read_backend as backend
from rca176_loopback_mcp import result_object
from rca178_auth_lifecycle import ISSUER, READ_SCOPE, CLIENT, SUBJECT, atomic_state

def load_state(path, expected_digest):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    with path.open("rb") as f:
        raw=f.read(65537)
    if len(raw)>65536:
        raise ValueError("STATE_LIMIT")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),expected_digest):
        raise ValueError("STATE_DIGEST_MISMATCH")
    data=json.loads(raw)
    if type(data) is not dict or set(data)!={"schema","keys","revoked"} or data["schema"]!=1:
        raise ValueError("STATE_SCHEMA")
    keys,revoked=data["keys"],data["revoked"]
    if type(keys) is not dict or not 1<=len(keys)<=4 or type(revoked) is not list or len(revoked)>512:
        raise ValueError("STATE_SHAPE")
    if any(not isinstance(x,str) or not re.fullmatch(r"[0-9a-f]{32}",x) for x in revoked):
        raise ValueError("REVOCATION_FORMAT")
    result={}
    for kid,pem in keys.items():
        if not isinstance(kid,str) or not re.fullmatch(r"[a-z0-9-]{1,32}",kid) or not isinstance(pem,str):
            raise ValueError("KEY_FORMAT")
        key=serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(key,rsa.RSAPublicKey) or key.key_size<2048:
            raise ValueError("KEY_TYPE")
        result[kid]=key
    return result,frozenset(revoked)

class SignedTestVerifier:
    def __init__(self, state_path, resource, expected_digest):
        self.expected_digest=expected_digest
        self.state_path = state_path
        self.resource = resource

    async def verify_token(self, token):
        import jwt
        from mcp.server.auth.provider import AccessToken
        if not isinstance(token,str) or len(token)>8192:
            return None
        try:
            header=jwt.get_unverified_header(token)
            if header.get("alg")!="RS256" or header.get("typ")!="at+jwt":
                return None
            keys,revoked=load_state(self.state_path,self.expected_digest)
            kid=header.get("kid")
            if not isinstance(kid,str) or kid not in keys:
                return None
            claims=jwt.decode(token,keys[kid],algorithms=["RS256"],
                issuer=ISSUER,audience=self.resource,
                options={"require":["iss","aud","exp","iat","nbf","sub","client_id","scope","jti"],
                         "strict_aud":True})
            if not isinstance(claims["jti"],str) or not re.fullmatch(r"[0-9a-f]{32}",claims["jti"]) or claims["jti"] in revoked:
                return None
            if claims["client_id"]!=CLIENT or claims["sub"]!=SUBJECT:
                return None
            if any(type(claims[k]) is not int for k in ("exp","iat","nbf")):
                return None
            if not 0 < claims["exp"]-claims["iat"] <= 120:
                return None
            scope=claims["scope"]
            if not isinstance(scope,str) or len(scope)>128:
                return None
            scopes=scope.split()
            if any(s not in {READ_SCOPE} for s in scopes):
                return None
            return AccessToken(token=token,client_id=CLIENT,subject=SUBJECT,
                scopes=scopes,expires_at=claims["exp"],resource=self.resource)
        except (jwt.PyJWTError,ValueError,TypeError,KeyError,OSError):
            return None


def serve(fd, mirror, state, digest, resource):
    import uvicorn
    from mcp.server import MCPServer
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.auth.middleware.auth_context import get_access_token
    from pydantic import AnyHttpUrl
    sock=socket.socket(fileno=fd)
    if sock.getsockname()[0]!="127.0.0.1":
        raise ValueError("NON_LOOPBACK")
    if not re.fullmatch(r"[0-9a-f]{64}",digest):
        raise ValueError("INVALID_DIGEST")
    verifier=SignedTestVerifier(state,resource,digest)
    mcp=MCPServer("PCFM public restart proof",token_verifier=verifier,
        auth=AuthSettings(issuer_url=AnyHttpUrl(ISSUER),
            resource_server_url=AnyHttpUrl(resource),
            required_scopes=[READ_SCOPE],validate_token_resource=True))
    @mcp.tool()
    def fetch(id:str)->dict:
        """Fetch only the pinned public README."""
        token=get_access_token()
        if token is None or READ_SCOPE not in token.scopes or token.resource!=resource:
            raise ValueError("READ_AUTH_REQUIRED")
        if id!=backend.SNAPSHOT_SHA+":README.md":
            raise ValueError("DOCUMENT_ID_DENIED")
        return backend.dispatch(mirror,backend.SNAPSHOT_SHA,"fetch",{"path":"README.md"},
                                backend.safe_git_environment())
    app=mcp.streamable_http_app(json_response=True,stateless_http=True)
    server=uvicorn.Server(uvicorn.Config(app,log_level="warning",access_log=False,
                          lifespan="on",timeout_graceful_shutdown=3))
    asyncio.run(server.serve(sockets=[sock]))

async def test(mirror):
    import jwt
    import httpx2
    from cryptography.hazmat.primitives.asymmetric import rsa
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    state=mirror.parent/"state.json"
    oldkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    newkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    revoked_id=secrets.token_hex(16)
    atomic_state(state,{"old":oldkey.public_key(),"new":newkey.public_key()},set())
    stale=state.read_bytes()
    atomic_state(state,{"new":newkey.public_key()},{revoked_id})
    current=state.read_bytes()
    digest=hashlib.sha256(current).hexdigest()
    if digest==hashlib.sha256(stale).hexdigest():
        raise RuntimeError("STATE_NOT_CHANGED")
    statuses={}
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1",0))
        sock.listen(16)
        base=f"http://127.0.0.1:{sock.getsockname()[1]}"
        resource=base+"/mcp"
        def mint(key,kid,jti):
            now=int(time.time())
            return jwt.encode({"iss":ISSUER,"aud":resource,"sub":SUBJECT,"client_id":CLIENT,
                  "scope":READ_SCOPE,"iat":now,"nbf":now,"exp":now+115,"jti":jti},
                  key,algorithm="RS256",headers={"typ":"at+jwt","kid":kid})
        active=mint(newkey,"new",secrets.token_hex(16))
        revoked=mint(newkey,"new",revoked_id)
        retired=mint(oldkey,"old",secrets.token_hex(16))
        child=None
        pids=[]
        async with httpx2.AsyncClient(trust_env=False,timeout=3.0) as probe:
            async def start():
                nonlocal child
                child=subprocess.Popen([sys.executable,__file__,"--serve",str(sock.fileno()),
                   str(mirror),str(state),digest,resource],pass_fds=(sock.fileno(),),
                   stdin=subprocess.DEVNULL)
                pids.append(child.pid)
                for _ in range(80):
                    if child.poll() is not None:
                        raise RuntimeError("CHILD_EXITED")
                    try:
                        response=await probe.get(base+"/.well-known/oauth-protected-resource/mcp",
                                                 timeout=.3)
                        if response.status_code==200:
                            return
                    except httpx2.HTTPError:
                        pass
                    await asyncio.sleep(.05)
                raise RuntimeError("CHILD_NOT_READY")
            def stop():
                nonlocal child
                if child is not None:
                    if child.poll() is None: child.kill()
                    code=child.wait(timeout=8)
                    child=None
                    return code
            async def deny(name,value):
                response=await probe.post(resource,headers={
                   "Authorization":"Bearer "+value,"Accept":"application/json, text/event-stream",
                   "MCP-Protocol-Version":"2026-07-28"},json={"jsonrpc":"2.0","id":1,
                   "method":"tools/call","params":{"name":"fetch","arguments":{
                       "id":backend.SNAPSHOT_SHA+":README.md"}}})
                if response.status_code!=401:
                    raise RuntimeError("EXPECTED_401_"+name+"_"+str(response.status_code))
                statuses[name]=401
            async def allow(name):
                async with (httpx2.AsyncClient(headers={"Authorization":"Bearer "+active},
                             trust_env=False,timeout=8.0) as hc,
                            Client(streamable_http_client(resource,http_client=hc)) as client):
                    doc=result_object(await client.call_tool("fetch",
                                       {"id":backend.SNAPSHOT_SHA+":README.md"}))
                    if hashlib.sha256(doc["text"].encode()).hexdigest()!=doc["sha256"]:
                        raise RuntimeError("HASH_MISMATCH")
                    if client.protocol_version!="2026-07-28":
                        raise RuntimeError("PROTOCOL_MISMATCH")
                    statuses[name]="MCP_FETCH_PASS"
            try:
                await start()
                await allow("before_stop_active")
                await deny("before_stop_revoked",revoked)
                await deny("before_stop_retired",retired)
                kill_code=stop()
                if kill_code!=-9:
                    raise RuntimeError("SIGKILL_NOT_OBSERVED")
                # Old authentic state remains structurally valid but lacks revocation.
                state.write_bytes(stale)
                await start()
                if pids[0]==pids[1]:
                    raise RuntimeError("PROCESS_ID_NOT_CHANGED")
                await deny("rollback_active",active)
                await deny("rollback_revoked",revoked)
                await deny("rollback_retired",retired)
                state.write_bytes(current)
                await allow("after_restart_restored_active")
                await deny("after_restart_revoked",revoked)
                await deny("after_restart_retired",retired)
                # Valid JSON with a changed revocation list must also be denied.
                changed=json.loads(current)
                changed["revoked"]=[]
                state.write_text(json.dumps(changed,sort_keys=True),encoding="utf-8")
                await deny("tampered_state_active",active)
                await deny("tampered_state_revoked",revoked)
                state.unlink()
                await deny("missing_state",active)
                state.write_bytes(current)
                await allow("after_recovery_active")
                await deny("after_recovery_revoked",revoked)
            finally:
                stop()
    return {"schema":"PCFM-RCA179-public-restart-integrity-v1",
            "observed_at_utc":datetime.now(timezone.utc).isoformat(),
            "process_ids":pids,"first_exit_code":kill_code,
            "full_subprocess_restart":"PASS","http_statuses":statuses,
            "trusted_test_state_digest":digest,"stale_state_digest":hashlib.sha256(stale).hexdigest(),
            "rollback_with_fixed_test_anchor":"DENIED","tamper_with_fixed_test_anchor":"DENIED",
            "anchor_custody":"PARENT_PROCESS_TEST_ONLY",
            "anchor_rollback_resistance":"NOT_ESTABLISHED",
            "power_loss_durability":"NOT_TESTED","external_oauth":"NOT_CONNECTED",
            "native_write_denial":"NOT_ESTABLISHED","production":"BLOCKED"}

async def main():
    env=backend.safe_git_environment()
    with TemporaryDirectory(prefix="pcfm-rca179-") as temp:
        mirror=Path(temp)/"mirror.git"
        backend._exec_git(["git","-c","credential.helper=","-c","protocol.allow=never",
                           "-c","protocol.https.allow=always","clone","--mirror","--",
                           backend.PUBLIC_REMOTE,str(mirror)],env,limit=65536)
        report=await asyncio.wait_for(test(mirror),timeout=75)
        print(json.dumps(report,sort_keys=True,separators=(",",":")))

if __name__=="__main__":
    if len(sys.argv)==7 and sys.argv[1]=="--serve":
        serve(int(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),sys.argv[5],sys.argv[6])
    elif len(sys.argv)==1:
        asyncio.run(main())
    else:
        raise SystemExit(2)
