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
def server(config, state, scheduled=False):
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryFile(mode="w+b") as log:
        p = subprocess.Popen([str(ROOT/"node_modules/.bin/wrangler"),"dev","--config",config,
            "--local","--ip","127.0.0.1","--port",str(port),"--persist-to",str(state)] + (["--test-scheduled"] if scheduled else []),
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

# Generic synthetic scheduled integration, generated only in a temporary local directory.
# Never deploy this fixture. The clock is injected: no hosted timing assurance.
from urllib.parse import urlencode

SCHEDULED_ENTRY = "// Generated CI-only fixture. No deploy, credentials, live data, or configured triggers.\nimport { Checkpoint } from \"../src/worker.js\";\nexport { Checkpoint };\nexport async function runProbe(env, controller, slotMs, cron, nowMs) {\n  const name = \"public-synthetic-scheduled-fixture\";\n  const z = \"0\".repeat(64), a = \"a\".repeat(64), b = \"b\".repeat(64), c = \"c\".repeat(64);\n  if (!Number.isSafeInteger(slotMs) || slotMs % 60000 !== 0 || !Number.isSafeInteger(nowMs) ||\n      typeof cron !== \"string\" || !cron || controller?.cron !== cron ||\n      controller?.scheduledTime !== slotMs || nowMs < slotMs || nowMs >= slotMs + 300000)\n    return { result: \"SKIP_OUTSIDE_WINDOW\" };\n  const stub = env.CHECKPOINT.get(env.CHECKPOINT.idFromName(name));\n  function check(condition, label) { if (!condition) throw new Error(label); }\n  function same(value, generation, digest) { return value?.generation === generation && value?.digest === digest; }\n  const initial = await stub.current();\n  if (!same(initial, 0, z)) return {result: \"STOP_NONINITIAL_STATE\"};\n  const first = await stub.advance(0, z, a);\n  if (first?.result !== \"COMMITTED\") return {result: \"STOP_INITIAL_CAS\"};\n  check(same(first, 1, a), \"FIRST_COMMIT\");\n  check((await stub.advance(0, z, b))?.result === \"CONFLICT\", \"STALE_REJECT\");\n  check((await stub.advance(1, \"bad\", b))?.result === \"INVALID\", \"DIGEST_REJECT\");\n  check((await stub.advance(true, a, b))?.result === \"INVALID\", \"TYPE_REJECT\");\n  check((await stub.advance(1, a, a))?.result === \"INVALID\", \"SAME_DIGEST_REJECT\");\n  check(same(await stub.current(), 1, a), \"UNCHANGED_AFTER_REJECTS\");\n  const pair = await Promise.allSettled([stub.advance(1,a,b), stub.advance(1,a,c)]);\n  check(pair.every(x => x.status === \"fulfilled\"), \"RPC_FAILURE\");\n  const values = pair.map(x => x.value);\n  check(values.map(x=>x?.result).sort().join(\",\") === \"COMMITTED,CONFLICT\", \"CAS_OUTCOMES\");\n  const winner = values[0]?.result === \"COMMITTED\" ? b : c;\n  check(same(values.find(x=>x?.result===\"COMMITTED\"), 2, winner), \"WINNER_RESPONSE\");\n  const final = await stub.current();\n  check(same(final, 2, winner), \"FINAL_STATE\");\n  return {result:\"PASS\", instance:name, generation:2, digest:winner, outcomes:values.map(x=>x.result)};\n}\n\nexport function buildScheduled(probe, config, clock = Date.now, emit = console.log) {\n  return async function scheduled(controller, env) {\n    const slot = config?.slotMs;\n    const now = clock();\n    const d = new Date(slot);\n    const exactCron = Number.isFinite(d.getTime()) ? `${d.getUTCMinutes()} ${d.getUTCHours()} ${d.getUTCDate()} ${d.getUTCMonth()+1} *` : \"\";\n    const report = (result, extra={}) => emit({event:\"SYNTHETIC_RPC_PROBE\",result,slotMs:Number.isSafeInteger(slot)?slot:null,...extra});\n    if(config?.armed !== true || !Number.isSafeInteger(slot) || slot<=0 || slot%60000!==0 || !exactCron || config.cron!==exactCron) {report(\"DISARMED_OR_INVALID\");return;}\n    if((controller?.type!=null && controller.type!==\"scheduled\") || controller.cron!==exactCron || controller.scheduledTime!==slot || !Number.isSafeInteger(now) || now<slot || now>=slot+300000) {report(\"SKIP_OUTSIDE_WINDOW\");return;}\n    report(\"START\");\n    try {\n      if (typeof controller.noRetry !== \"function\") throw Error(\"NO_RETRY_UNAVAILABLE\");\n      controller.noRetry();\n      const r=await probe(env,controller,slot,exactCron,now);\n      if(r?.result===\"STOP_NONINITIAL_STATE\" || r?.result===\"STOP_INITIAL_CAS\"){report(r.result);return;}\n      if(r?.result!==\"PASS\" || r.generation!==2 || !/^[bc]$/.test(r.digest?.[0]||\"\") || r.digest!==r.digest[0].repeat(64) || !Array.isArray(r.outcomes) || [...r.outcomes].sort().join(\",\")!==\"COMMITTED,CONFLICT\") throw Error(\"INVALID_PROBE_RESULT\");\n      report(\"PASS\",{generation:r.generation,digest:r.digest,outcomes:r.outcomes});\n    } catch {report(\"FAIL_OR_PARTIAL_STATE\");throw Error(\"SYNTHETIC_RPC_PROBE_FAILED\");}\n  }\n}\n\nconst slot=Date.UTC(2030,0,2,3,4), cron=\"4 3 2 1 *\";\nconst config=Object.freeze({armed:true,slotMs:slot,cron});\nexport default {\n  async scheduled(controller,env) {\n    console.log({event:\"SYNTHETIC_CONTROLLER_DIAGNOSTIC\",type:controller.type??null,cron:controller.cron,scheduledTime:controller.scheduledTime,expectedSlot:slot,noRetryType:typeof controller.noRetry});\n    return buildScheduled(runProbe,config,()=>slot)(controller,env);\n  },\n  async fetch(request, env) {\n    if(request.method===\"GET\" && new URL(request.url).pathname===\"/fixture/state\"){\n      const stub=env.CHECKPOINT.get(env.CHECKPOINT.idFromName(\"public-synthetic-scheduled-fixture\"));\n      return Response.json(await stub.current());\n    }\n    return new Response(\"NOT_ENABLED\",{status:403});\n  }\n};\n"
# Python JSON string syntax here is identical to a quoted string for this ASCII source.
def fire(url, cron, slot):
    status, data = req(url, "/cdn-cgi/handler/scheduled?" + urlencode(
        {"format":"json", "cron":cron, "time":str(slot)}))
    assert status == 200, (status, data)
    result = json.loads(data)
    assert result["outcome"] == "ok", result
    return result

with tempfile.TemporaryDirectory(dir=ROOT, prefix="scheduled-fixture-") as tmp, tempfile.TemporaryDirectory() as state:
    tmp = Path(tmp)
    (tmp/"entry.js").write_text(SCHEDULED_ENTRY, encoding="utf-8")
    config = json.loads((ROOT/"wrangler.fixture.json").read_text(encoding="utf-8"))
    config["name"] = "synthetic-scheduled-local-only"
    config["main"] = "entry.js"
    assert config.get("workers_dev") is False and config.get("preview_urls") is False
    assert "triggers" not in config
    (tmp/"wrangler.json").write_text(json.dumps(config), encoding="utf-8")
    # Derive the same fixed synthetic UTC timestamp as the JS fixture, not wall time.
    import datetime
    slot = int(datetime.datetime(2030,1,2,3,4,tzinfo=datetime.timezone.utc).timestamp()*1000)
    cron = "4 3 2 1 *"
    with server(str(tmp/"wrangler.json"), Path(state), scheduled=True) as url:
        initial = get(url)
        assert initial == {"generation":0,"digest":ZERO}
        fire(url, "5 3 2 1 *", slot)
        assert get(url) == initial
        fire(url, cron, slot+60000)
        assert get(url) == initial
        assert req(url,"/")[0] == 403
        result = fire(url, cron, slot)
        assert result["noRetry"] is True, result
        saved = get(url)
        assert saved["generation"] == 2 and saved["digest"] in (B,C), saved
        assert fire(url, cron, slot)["noRetry"] is True
        assert get(url) == saved
        print("SYNTHETIC_SCHEDULED_RPC_CAS=PASS",flush=True)
    with server(str(tmp/"wrangler.json"), Path(state), scheduled=True) as url:
        assert get(url) == saved
        assert fire(url, cron, slot)["noRetry"] is True
        assert get(url) == saved
        print("SYNTHETIC_SCHEDULED_RESTART_NO_WRITE=PASS",flush=True)
print("SYNTHETIC_HOSTED_CRON=NOT_RUN",flush=True)
