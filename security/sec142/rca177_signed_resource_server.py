"""RCA177: signed synthetic access tokens through official MCP HTTP auth.

Ephemeral test issuer/key; no production OAuth provider, secrets, private data,
public listener or GitHub write authority. A valid bearer is replayable until
expiry; this test does not claim proof-of-possession or revocation.
"""
import asyncio
from datetime import datetime, timezone
import hashlib
import json
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

class SignedTestVerifier:
    def __init__(self, public_key, resource):
        self.public_key = public_key
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
            claims=jwt.decode(token,self.public_key,algorithms=["RS256"],
                issuer=ISSUER,audience=self.resource,
                options={"require":["iss","aud","exp","iat","nbf","sub","client_id","scope"],
                         "strict_aud":True})
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
        except (jwt.PyJWTError,ValueError,TypeError,KeyError):
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
    counts={"search":0,"fetch":0}
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1",0))
        sock.listen(16)
        base=f"http://127.0.0.1:{sock.getsockname()[1]}"
        resource=base+"/mcp"
        verifier=SignedTestVerifier(private.public_key(),resource)
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
        def mint(changes=None,key=None,typ="at+jwt"):
            now=int(time.time())
            claims={"iss":ISSUER,"aud":resource,"sub":SUBJECT,"client_id":CLIENT,
                    "scope":READ_SCOPE,"iat":now,"nbf":now,"exp":now+90}
            for k,v in (changes or {}).items():
                if v is None: claims.pop(k,None)
                else: claims[k]=v
            return jwt.encode(claims,key or private,algorithm="RS256",headers={"typ":typ})
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
            now=int(time.time())
            cases={
                "missing":(None,401),
                "malformed":("invalid",401),
                "wrong_signature":(mint(key=wrong_key),401),
                "wrong_issuer":(mint({"iss":"https://untrusted.invalid"}),401),
                "wrong_audience":(mint({"aud":base+"/other"}),401),
                "expired":(mint({"iat":now-90,"nbf":now-90,"exp":now-1}),401),
                "future_nbf":(mint({"nbf":now+60}),401),
                "missing_exp":(mint({"exp":None}),401),
                "wrong_subject":(mint({"sub":"wrong-subject"}),401),
                "wrong_client":(mint({"client_id":"wrong-client"}),401),
                "wrong_token_type":(mint(typ="JWT"),401),
                "write_scope":(mint({"scope":"pcfm:write"}),401),
                "insufficient_scope":(mint({"scope":""}),403),
            }
            statuses={}
            async with httpx2.AsyncClient(trust_env=False,timeout=8.0) as probe:
                metadata=await probe.get(base+"/.well-known/oauth-protected-resource/mcp")
                metadata.raise_for_status()
                meta=metadata.json()
                if meta["resource"]!=resource or READ_SCOPE not in meta["scopes_supported"]:
                    raise RuntimeError("RESOURCE_METADATA_MISMATCH")
                if [s.rstrip("/") for s in meta["authorization_servers"]]!=[ISSUER]:
                    raise RuntimeError("ISSUER_METADATA_MISMATCH")
                for name,(value,expected) in cases.items():
                    headers={"Accept":"application/json, text/event-stream",
                             "MCP-Protocol-Version":"2026-07-28"}
                    if value is not None: headers["Authorization"]="Bearer "+value
                    response=await probe.post(resource,headers=headers,json={
                         "jsonrpc":"2.0","id":1,"method":"tools/call",
                         "params":{"name":"fetch","arguments":{"id":backend.SNAPSHOT_SHA+":README.md"}}})
                    statuses[name]=response.status_code
                    if response.status_code!=expected:
                        raise RuntimeError("UNEXPECTED_AUTH_STATUS_"+name+"_"+str(response.status_code))
                if any(counts.values()): raise RuntimeError("DENIED_HANDLER_EXECUTED")
            async with (httpx2.AsyncClient(headers={"Authorization":"Bearer "+mint()},
                           trust_env=False,timeout=10.0) as http_client,
                        Client(streamable_http_client(resource,http_client=http_client)) as client):
                names=sorted(t.name for t in (await client.list_tools()).tools)
                if names!=["fetch","search"]: raise RuntimeError("UNEXPECTED_TOOLS")
                rows=result_object(await client.call_tool("search",{"query":"runner"}))["results"]
                doc=result_object(await client.call_tool("fetch",{"id":rows[0]["id"]}))
                digest=hashlib.sha256(doc["text"].encode("utf-8")).hexdigest()
                if digest!=doc["sha256"]: raise RuntimeError("DOCUMENT_HASH_MISMATCH")
                if client.protocol_version!="2026-07-28": raise RuntimeError("PROTOCOL_MISMATCH")
                if counts!={"search":1,"fetch":1}: raise RuntimeError("HANDLER_COUNT_MISMATCH")
            return {"schema":"PCFM-RCA177-signed-test-resource-server-v1",
                    "observed_at_utc":datetime.now(timezone.utc).isoformat(),
                    "http_negative_statuses":statuses,"denied_handler_calls":0,
                    "metadata_check":"PASS","authenticated_read":"PASS",
                    "document_sha256":digest,"handler_calls":counts,
                    "test_issuer_only":True,"private_data_used":False,
                    "external_oauth_provider":"NOT_CONNECTED","production":"BLOCKED",
                    "revocation":"NOT_IMPLEMENTED","bearer_replay_protection":"NOT_IMPLEMENTED",
                    "chatgpt_connection":"NOT_TESTED","native_write_denial":"NOT_ESTABLISHED"}
        finally:
            server.should_exit=True
            await asyncio.wait_for(task,timeout=8)

async def main():
    env=backend.safe_git_environment()
    with TemporaryDirectory(prefix="pcfm-rca177-") as temp:
        mirror=Path(temp)/"mirror.git"
        backend._exec_git(["git","-c","credential.helper=","-c","protocol.allow=never",
                           "-c","protocol.https.allow=always","clone","--mirror","--",
                           backend.PUBLIC_REMOTE,str(mirror)],env,limit=65536)
        result=await asyncio.wait_for(run_http(mirror,env),timeout=60)
        print(json.dumps(result,sort_keys=True,separators=(",",":")))

if __name__=="__main__":
    asyncio.run(main())
