#!/usr/bin/env bash
# Public fixture only. No user-PC evidence or private repository code.
set -euo pipefail
umask 077
export TZ=UTC LC_ALL=C

RELEASE_URL='https://github.com/Yamato-Security/hayabusa/releases/download/v4.3.1/hayabusa-4.3.1-lin-x64-gnu.zip'
RELEASE_SHA256='a4fbdae9b13a5fe0f3b3d98981dd18775f50e5402cf3dee3ba85d4ecd252370e'
SAMPLE_URL='https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/0845333ecb4afcf64c55c6e10946383f168f308c/YamatoSecurity/CredentialAccess/T1558.003_StealOrForgeKerberosTicketsKerberoasting_Security.evtx'
SAMPLE_GIT_BLOB='3dae16bd9baa14e58d934cc335d5bdab5c69ae62'

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *) echo 'Only disposable Ubuntu x64 GitHub runner is supported' >&2; exit 20 ;;
esac
: "${RUNNER_TEMP:?Requires a disposable GitHub-hosted runner}"
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(mktemp -d "$RUNNER_TEMP/pcfm-hybrid-fixture.XXXXXXXX")"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir -p "$ROOT/pkg" "$ROOT/results"

curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 "$RELEASE_URL" -o "$ROOT/hayabusa.zip"
echo "$RELEASE_SHA256  $ROOT/hayabusa.zip" | sha256sum --check --status

authored_zip_guard() {
 python3 - "$ROOT/hayabusa.zip" <<'PY'
import pathlib, stat, sys, zipfile
p = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(p) as z:
    seen = set()
    for item in z.infolist():
        normalized = pathlib.PurePosixPath(item.filename)
        if normalized.is_absolute() or '..' in normalized.parts or '\\' in item.filename or len(item.filename) > 300:
            raise SystemExit('unsafe archive path')
        if item.filename in seen:
            raise SystemExit('duplicate archive member')
        seen.add(item.filename)
        if stat.S_ISLNK(item.external_attr >> 16):
            raise SystemExit('archive symlink not allowed')
    if len(seen) < 2 or len(seen) > 30000:
        raise SystemExit('unexpected archive member count')
PY
}
authored_zip_guard
unzip -q "$ROOT/hayabusa.zip" -d "$ROOT/pkg"
mapfile -t matches < <(find "$ROOT/pkg" -type f -name 'hayabusa*lin*x64*gnu' -print)
if (( ${#matches[@]} != 1 )); then
 echo 'expected exactly one Linux GNU Hayabusa binary in release' >&2
 exit 21
fi
BIN="${matches[0]}"
chmod u+x "$BIN"

curl -fLsS --retry 2 --connect-timeout 15 --max-time 60 "$SAMPLE_URL" -o "$ROOT/fixture.evtx"
if [[ "$(stat -c '%s' "$ROOT/fixture.evtx")" != 69632 ]] || [[ "$(git hash-object "$ROOT/fixture.evtx")" != "$SAMPLE_GIT_BLOB" ]]; then
 echo 'sample EVTX does not match pinned Git object/size' >&2
 exit 22
fi
cp "$ROOT/fixture.evtx" "$ROOT/original.evtx"
INPUT_SHA256="$(sha256sum "$ROOT/fixture.evtx" | awk '{print $1}')"

# Only a public, fixed EVTX fixture is analyzed. It is never executed.
# The release archive includes its own pinned rules, covered by its SHA-256.
cd "$(dirname "$BIN")"
timeout 180 "$BIN" dfir-timeline -f "$ROOT/fixture.evtx" -t jsonl -p verbose -b -O -o "$ROOT/results/first.jsonl" -w -s -U -q --threads 2
timeout 180 "$BIN" dfir-timeline -f "$ROOT/fixture.evtx" -t jsonl -p verbose -b -O -o "$ROOT/results/second.jsonl" -w -s -U -q --threads 2
cmp -s "$ROOT/fixture.evtx" "$ROOT/original.evtx" || { echo 'input EVTX was modified' >&2; exit 23; }
[[ "$(sha256sum "$ROOT/fixture.evtx" | awk '{print $1}')" == "$INPUT_SHA256" ]] || exit 24

python3 - "$ROOT/results/first.jsonl" "$ROOT/results/second.jsonl" <<'PY'
import hashlib, json, pathlib, sys
records = []
for filename in sys.argv[1:]:
    data = pathlib.Path(filename).read_bytes()
    if len(data) > 50_000_000:
        raise SystemExit('output exceeds declared 50MB budget')
    found = []
    for ln in data.splitlines():
        if ln.strip():
            obj = json.loads(ln)
            if not isinstance(obj, dict):
                raise SystemExit('non-object JSONL record')
            found.append(obj)
    records.append((len(found), hashlib.sha256(data).hexdigest()))
if records[0][0] == 0:
    raise SystemExit('no output records: this fixture cannot validate detection coverage')
if records[0] != records[1]:
    raise SystemExit('same-input analysis is not byte-reproducible')
print('PCFM_HYBRID_PUBLIC_EVTX_PASS records=%d output_sha256=%s' % records[0])
PY
# Validate parser-reported evidence references without falsely claiming source-EVTX
# verification. Two independent outputs must generate identical receipts.
python3 "$SCRIPT_ROOT/hayabusa_event_receipt.py" --jsonl "$ROOT/results/first.jsonl" --input-sha256 "$INPUT_SHA256" --expected-records 9 --report "$ROOT/results/receipt-first.json"
python3 "$SCRIPT_ROOT/hayabusa_event_receipt.py" --jsonl "$ROOT/results/second.jsonl" --input-sha256 "$INPUT_SHA256" --expected-records 9 --report "$ROOT/results/receipt-second.json"
cmp -s "$ROOT/results/receipt-first.json" "$ROOT/results/receipt-second.json" || { echo 'linkage receipt not deterministic' >&2; exit 25; }
# Persist only a SANITIZED reference index across public Ubuntu/Windows jobs.
# Raw JSONL (including potential test message content) remains ephemeral.
PUBLIC_INDEX_DIR="$RUNNER_TEMP/pcfm-ops043-public-index"
if [[ -e "$PUBLIC_INDEX_DIR" ]]; then
 echo 'Refusing preexisting public index directory' >&2; exit 26
fi
mkdir -p "$PUBLIC_INDEX_DIR"
python3 "$SCRIPT_ROOT/public_evtx_reference_index.py" \
  --jsonl "$ROOT/results/first.jsonl" \
  --source-sha256 "$INPUT_SHA256" \
  --output "$PUBLIC_INDEX_DIR/reference-index.json"
printf 'PCFM_OPS043_PUBLIC_INDEX_ONLY=PASS\n'
printf 'PCFM_HYBRID_LINKAGE_RECEIPT_REPRODUCIBLE=PASS\n'
printf 'PCFM_HYBRID_INPUT_UNCHANGED=PASS sample_bytes=69632 sample_sha256=%s\n' "$INPUT_SHA256"
printf 'PCFM_HYBRID_HAYABUSA_RELEASE_SHA256=%s\n' "$RELEASE_SHA256"
printf 'PCFM_HYBRID_SCOPE=PUBLIC_SAMPLE_ONLY_NO_USER_PC_NO_NATIVE_ACQUISITION\n'
