"""RCA178: local test key rotation, revocation, unavailable state and reload via MCP HTTP. Not a production IdP."""
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import time

import rca175_mirror_read_backend as backend
from rca176_loopback_mcp import result_object

ISSUER = "https://rca177-test-issuer.invalid"
READ_SCOPE = "pcfm:read"
CLIENT = "rca177-test-client"
SUBJECT = "rca177-test-subject"

def atomic_state(path, keys, revoked):
    """Test administrator only; no model-accessible tool writes this file."""
    from cryptography.hazmat.primitives import serialization
    data={"schema":1,"keys":{k:v.public_bytes(serialization.Encoding.PEM,
          serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
          for k,v in keys.items()},"revoked":sorted(revoked)}
    tmp=path.with_suffix(".tmp")
    with tmp.open("x",encoding="utf-8") as f:
        json.dump(data,f,sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp,path)

def load_state(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    with path.open("rb") as f:
        raw=f.read(65537)
    if len(raw)>65536:
        raise ValueError("STATE_LIMIT")
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
    def __init__(self, state_path, resource):
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
            keys,revoked=load_state(self.state_path)
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

async def run_http(mirror,env):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server import MCPServer
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.types import ToolAnnotations
    from pydantic import AnyHttpUrl
    import httpx2
    import uvicorn

    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    wrong_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    state_path=mirror.parent/"test-auth-state.json"
    atomic_state(state_path,{"old":private.public_key()},set())
    counts={"search":0,"fetch":0}
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1",0))
        sock.listen(16)
        base=f"http://127.0.0.1:{sock.getsockname()[1]}"
        resource=base+"/mcp"
        verifier=SignedTestVerifier(state_path,resource)
        mcp=MCPServer("PCFM public signed token test",token_verifier=verifier,
            auth=AuthSettings(issuer_url=AnyHttpUrl(ISSUER),
                 resource_server_url=AnyHttpUrl(resource),
                 required_scopes=[READ_SCOPE],validate_token_resource=True))
        def require_read():
            token=get_access_token()
            if token is None or READ_SCOPE not in token.scopes or token.resource!=resource:
                raise ValueError("READ_AUTH_REQUIRED")
        @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
        def search(query:str)->dict:
            """Read only a fixed public snapshot."""
            require_read()
            rows=backend.dispatch(mirror,backend.SNAPSHOT_SHA,"search",{"query":query},env)
            counts["search"]+=1
            return {"results":[{k:rows[0][k] for k in ("id","title","url")}] if rows else []}
        @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
        def fetch(id:str)->dict:
            """Fetch one immutable public README."""
            require_read()
            if id!=backend.SNAPSHOT_SHA+":README.md":
                raise ValueError("DOCUMENT_ID_DENIED")
            result=backend.dispatch(mirror,backend.SNAPSHOT_SHA,"fetch",{"path":"README.md"},env)
            counts["fetch"]+=1
            return result
        def mint(changes=None,key=None,typ="at+jwt",kid="old"):
            now=int(time.time())
            claims={"iss":ISSUER,"aud":resource,"sub":SUBJECT,"client_id":CLIENT,
                    "scope":READ_SCOPE,"iat":now,"nbf":now,"exp":now+90,"jti":secrets.token_hex(16)}
            for k,v in (changes or {}).items():
                if v is None: claims.pop(k,None)
                else: claims[k]=v
            return jwt.encode(claims,key or private,algorithm="RS256",headers={"typ":typ,"kid":kid})
        app=mcp.streamable_http_app(json_response=True,stateless_http=True)
        server=uvicorn.Server(uvicorn.Config(app,log_level="warning",access_log=False,
                           lifespan="on",timeout_graceful_shutdown=3))
        task=asyncio.create_task(server.serve(sockets=[sock]))
        try:
            for _ in range(100):
                if server.started: break
                if task.done(): raise RuntimeError("SERVER_START_FAILED")
                await asyncio.sleep(.05)
            if not server.started: raise RuntimeError("SERVER_START_TIMEOUT")
            old=mint()
            rotated=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            new=mint(key=rotated,kid="new")
            revoked_id=secrets.token_hex(16)
            revoked=mint({"jti":revoked_id},key=rotated,kid="new")
            statuses={}
            async with httpx2.AsyncClient(trust_env=False,timeout=8.0) as probe:
                async def request(name,value,expected):
                    before=dict(counts)
                    response=await probe.post(resource,headers={
                        "Authorization":"Bearer "+value,
                        "Accept":"application/json, text/event-stream",
                        "MCP-Protocol-Version":"2026-07-28"},json={
                        "jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":"fetch","arguments":{"id":backend.SNAPSHOT_SHA+":README.md"}}})
                    statuses[name]=response.status_code
                    if response.status_code!=expected:
                        raise RuntimeError("STATUS_"+name+"_"+str(response.status_code))
                    if expected!=200 and counts!=before:
                        raise RuntimeError("DENIED_HANDLER_EXECUTED_"+name)
                    if expected==200:
                        payload=response.json()
                        result=payload.get("result",{})
                        if result.get("isError") or counts["fetch"]!=before["fetch"]+1:
                            raise RuntimeError("VALID_FETCH_FAILED_"+name)
                        document=json.loads(result["content"][0]["text"])
                        if hashlib.sha256(document["text"].encode()).hexdigest()!=document["sha256"]:
                            raise RuntimeError("HASH_MISMATCH")
                await request("initial_old",old,200)
                await request("unknown_new_kid",new,401)
                atomic_state(state_path,{"old":private.public_key(),"new":rotated.public_key()},set())
                await request("overlap_old",old,200)
                await request("overlap_new",new,200)
                await request("before_revocation",revoked,200)
                atomic_state(state_path,{"new":rotated.public_key()},{revoked_id})
                await request("retired_old",old,401)
                await request("revoked",revoked,401)
                await request("active_new",new,200)
                # Reopen from disk with a fresh verifier; not a full process restart.
                fresh=SignedTestVerifier(state_path,resource)
                if await fresh.verify_token(revoked) is not None or await fresh.verify_token(old) is not None:
                    raise RuntimeError("RELOAD_LOST_DENIAL")
                if await fresh.verify_token(new) is None:
                    raise RuntimeError("RELOAD_LOST_VALID_KEY")
                saved=state_path.read_bytes()
                state_path.unlink()
                await request("state_missing",new,401)
                state_path.write_bytes(b"not-json")
                await request("state_corrupt",new,401)
                state_path.unlink()
                atomic_state(state_path,{"new":rotated.public_key()},{revoked_id})
                if state_path.read_bytes()!=saved:
                    raise RuntimeError("RESTORE_STATE_MISMATCH")
                await request("restored_new",new,200)
                await request("restored_revoked",revoked,401)
                await request("restored_old",old,401)
            if counts!={"search":0,"fetch":6}:
                raise RuntimeError("HANDLER_COUNT_MISMATCH")
            return {"schema":"PCFM-RCA178-local-auth-state-v1",
                    "observed_at_utc":datetime.now(timezone.utc).isoformat(),
                    "http_statuses":statuses,"denied_handler_calls":0,
                    "handler_calls":counts,"fresh_verifier_reload":"PASS",
                    "full_process_restart":"NOT_TESTED",
                    "local_state_restore":"PASS","test_issuer_only":True,
                    "remote_jwks":"NOT_IMPLEMENTED","external_revocation":"NOT_IMPLEMENTED",
                    "state_tamper_or_rollback_resistance":"NOT_ESTABLISHED",
                    "external_oauth_provider":"NOT_CONNECTED","private_data_used":False,
                    "native_write_denial":"NOT_ESTABLISHED","production":"BLOCKED"}
        finally:
            server.should_exit=True
            await asyncio.wait_for(task,timeout=8)

async def main():
    env=backend.safe_git_environment()
    with TemporaryDirectory(prefix="pcfm-rca178-") as temp:
        mirror=Path(temp)/"mirror.git"
        backend._exec_git(["git","-c","credential.helper=","-c","protocol.allow=never",
                           "-c","protocol.https.allow=always","clone","--mirror","--",
                           backend.PUBLIC_REMOTE,str(mirror)],env,limit=65536)
        result=await asyncio.wait_for(run_http(mirror,env),timeout=60)
        print(json.dumps(result,sort_keys=True,separators=(",",":")))

if __name__=="__main__":
    asyncio.run(main())
