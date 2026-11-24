"""RCA186 local workerd subprocess tests; no account or deploy credentials."""
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
ZERO = "0" * 64
A = "a" * 64
B = "b" * 64
C = "c" * 64

@contextmanager
def server(config, state):
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryFile(mode="w+b") as log:
        p = subprocess.Popen([str(ROOT/"node_modules/.bin/wrangler"),"dev","--config",config,
            "--local","--ip","127.0.0.1","--port",str(port),"--persist-to",str(state)],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            for _ in range(100):
                if p.poll() is not None:
                    raise RuntimeError("local worker exited")
                try:
                    req(url, "/ready")
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(.2)
            else:
                raise RuntimeError("local worker start timeout")
            yield url
        except BaseException:
            log.seek(0)
            print(log.read().decode(errors="replace")[-8000:], flush=True)
            raise
        finally:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()

def req(url, path, data=None):
    payload = None if data is None else json.dumps(data).encode()
    r = urllib.request.Request(url+path, data=payload, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def get(url):
    status, data = req(url,"/fixture/state")
    assert status == 200, (status,data)
    return json.loads(data)

def cas(url,n,prev,new):
    status,data = req(url,"/fixture/cas",{"expected":n,"previous":prev,"next":new})
    assert status == 200, (status,data)
    return json.loads(data)["result"]

with tempfile.TemporaryDirectory() as d:
    state = Path(d)
    with server("wrangler.json",state/"candidate") as url:
        for path in ("/","/fixture/state","/fixture/cas","/arbitrary"):
            assert req(url,path)[0] == 403
        assert req(url,"/fixture/cas",{"expected":0,"previous":ZERO,"next":A})[0] == 403
        print("RCA186_CANDIDATE_HTTP_DENY=PASS",flush=True)
    with server("wrangler.fixture.json",state/"fixture") as url:
        assert get(url) == {"generation":0,"digest":ZERO}
        assert cas(url,0,ZERO,A) == "COMMITTED"
        assert cas(url,0,ZERO,B) == "CONFLICT"
        assert cas(url,1,"bad",B) == "INVALID"
        assert cas(url,True,A,B) == "INVALID"
        assert cas(url,1,A,A) == "INVALID"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(cas,url,1,A,x) for x in (B,C)]
            assert sorted(f.result() for f in futures) == ["COMMITTED","CONFLICT"]
        saved = get(url)
        assert saved["generation"] == 2 and saved["digest"] in (B,C)
        print("RCA186_LOCAL_SQLITE_CAS=PASS",flush=True)
    with server("wrangler.fixture.json",state/"fixture") as url:
        assert get(url) == saved
        assert cas(url,1,A,B) == "CONFLICT"
        print("RCA186_LOCAL_RESTART_PERSISTENCE=PASS",flush=True)
print("RCA186_HOSTED_DEPLOYMENT=NOT_RUN")
print("RCA186_INDEPENDENT_ANCHOR=NOT_ESTABLISHED")
