#!/usr/bin/env bash
# GitHub-hosted Ubuntu only, public sample EVTX, no PC evidence.
set -euo pipefail
umask 077
export TZ=UTC LC_ALL=C
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || { echo 'GitHub-hosted Linux required' >&2; exit 20; }
: "${RUNNER_TEMP:?required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(mktemp -d "$RUNNER_TEMP/ops045.XXXXXXXX")"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir -p "$ROOT/pkg" "$ROOT/cases" "$RUNNER_TEMP/ops045-public-receipt"
URL='https://github.com/Yamato-Security/hayabusa/releases/download/v4.3.1/hayabusa-4.3.1-lin-x64-gnu.zip'
RELEASE_SHA='a4fbdae9b13a5fe0f3b3d98981dd18775f50e5402cf3dee3ba85d4ecd252370e'
curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 "$URL" -o "$ROOT/hayabusa.zip"
echo "$RELEASE_SHA  $ROOT/hayabusa.zip" | sha256sum -c --status
python3 - "$ROOT/hayabusa.zip" <<'PY'
import pathlib,stat,sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    if len(z.infolist()) > 30000: raise SystemExit('archive member budget exceeded')
    seen=set()
    for m in z.infolist():
        p=pathlib.PurePosixPath(m.filename)
        if p.is_absolute() or '..' in p.parts or '\\' in m.filename or m.filename in seen or stat.S_ISLNK(m.external_attr >> 16):
            raise SystemExit('unsafe archive member')
        seen.add(m.filename)
PY
unzip -q "$ROOT/hayabusa.zip" -d "$ROOT/pkg"
mapfile -t bins < <(find "$ROOT/pkg" -type f -name 'hayabusa*lin*x64*gnu' -print)
(( ${#bins[@]} == 1 )) || { echo 'binary missing/ambiguous' >&2; exit 21; }
BIN="${bins[0]}"; chmod u+x "$BIN"
BASE='https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/0845333ecb4afcf64c55c6e10946383f168f308c/YamatoSecurity/CredentialAccess'
for case_id in kerberoasting asrep_roasting; do
  mkdir -p "$ROOT/cases/$case_id"
  if [[ "$case_id" == kerberoasting ]]; then
    fname='T1558.003_StealOrForgeKerberosTicketsKerberoasting_Security.evtx'
    expected_blob='3dae16bd9baa14e58d934cc335d5bdab5c69ae62'
  else
    fname='T1558.004_StealOrForgeKerberosTicketsAS-REP-Roasting_Security.evtx'
    expected_blob='9b34ff50cabf78605368d0e4c1d70f256aa38aab'
  fi
  filepath="$ROOT/cases/$case_id/fixture.evtx"
  curl -fLsS --retry 2 --connect-timeout 15 --max-time 60 "$BASE/$fname" -o "$filepath"
  [[ "$(git hash-object "$filepath")" == "$expected_blob" ]] || { echo "git source mismatch $case_id" >&2; exit 22; }
  [[ "$(stat -c '%s' "$filepath")" == 69632 ]] || exit 23
  before_sha="$(sha256sum "$filepath" | awk '{print $1}')"
  printf '%s\n' "$before_sha" > "$ROOT/cases/$case_id/input-sha.txt"
  (cd "$(dirname "$BIN")" && timeout 180 "$BIN" dfir-timeline -f "$filepath" -t jsonl -p verbose -b -O -o "$ROOT/cases/$case_id/result.jsonl" -w -s -U -q --threads 2)
  [[ -f "$ROOT/cases/$case_id/result.jsonl" ]] || { echo "missing output $case_id" >&2; exit 24; }
  [[ "$(sha256sum "$filepath" | awk '{print $1}')" == "$before_sha" ]] || { echo "EVTX altered $case_id" >&2; exit 25; }
done
python3 "$SCRIPT_DIR/ops045_detection_contract.py" \
  --kerberos-jsonl "$ROOT/cases/kerberoasting/result.jsonl" \
  --asrep-jsonl "$ROOT/cases/asrep_roasting/result.jsonl" \
  --kerberos-sha "$(cat "$ROOT/cases/kerberoasting/input-sha.txt")" \
  --asrep-sha "$(cat "$ROOT/cases/asrep_roasting/input-sha.txt")" \
  --output "$RUNNER_TEMP/ops045-public-receipt/detection-control.json"
printf 'PCFM_OPS045_PUBLIC_INPUT_SHA_CONSISTENCY=PASS\n'
