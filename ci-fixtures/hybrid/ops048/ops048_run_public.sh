#!/usr/bin/env bash
# OPS048: pinned public synthetic OPS047 native EVTX, never PC evidence.
set -euo pipefail
umask 077
export TZ=UTC LC_ALL=C
[[ "$GITHUB_ACTIONS" == true && "$RUNNER_OS" == Linux && "$RUNNER_ENVIRONMENT" == github-hosted ]] || exit 25
: "$RUNNER_TEMP"
ROOT="$(mktemp -d "$RUNNER_TEMP/ops048.XXXXXXXX")"
trap 'rm -rf -- "$ROOT"' EXIT
SCRIPT_DIR="$(cd "$(dirname "$BASH_SOURCE")" && pwd)"
mkdir -p "$ROOT/pkg" "$RUNNER_TEMP/ops048-public-receipt"
URL='https://github.com/Yamato-Security/hayabusa/releases/download/v4.3.1/hayabusa-4.3.1-lin-x64-gnu.zip'
RELEASE_SHA='a4fbdae9b13a5fe0f3b3d98981dd18775f50e5402cf3dee3ba85d4ecd252370e'
curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 "$URL" -o "$ROOT/hayabusa.zip"
echo "$RELEASE_SHA  $ROOT/hayabusa.zip" | sha256sum -c --status
python3 - "$ROOT/hayabusa.zip" <<'PY'
import pathlib,stat,sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    if len(z.infolist()) > 30000: raise SystemExit("too many files")
    names=set()
    for f in z.infolist():
        p=pathlib.PurePosixPath(f.filename)
        if p.is_absolute() or '..' in p.parts or '\\' in f.filename or f.filename in names or stat.S_ISLNK(f.external_attr>>16):
            raise SystemExit("unsafe ZIP member")
        names.add(f.filename)
PY
unzip -q "$ROOT/hayabusa.zip" -d "$ROOT/pkg"
mapfile -t bins < <(find "$ROOT/pkg" -type f -name 'hayabusa*lin*x64*gnu' -print)
(( ${#bins[@]} == 1 )) || { echo 'Ambiguous analyzer binary' >&2; exit 26; }
BIN="${bins[0]}"; chmod u+x "$BIN"
for os in windows-2022 windows-2025; do
  src="$GITHUB_WORKSPACE/ops048-upstream-$os"
  input="$src/controlled-application.evtx"
  [[ -f "$src/receipt.json" && -f "$input" ]] || { echo "Missing source $os" >&2; exit 27; }
  mkdir -p "$ROOT/$os"
  (cd "$(dirname "$BIN")" && timeout 180 "$BIN" dfir-timeline -f "$input" -t jsonl -p verbose -b -O -o "$ROOT/$os/result.jsonl" -w -s -U -q --threads 2)
  [[ -f "$ROOT/$os/result.jsonl" ]] || { echo "Analyzer did not produce JSONL ($os); do not treat as zero detections" >&2; exit 28; }
done
python3 "$SCRIPT_DIR/ops048_recordid_join.py" \
  --windows-2022-folder "$GITHUB_WORKSPACE/ops048-upstream-windows-2022" \
  --windows-2022-jsonl "$ROOT/windows-2022/result.jsonl" \
  --windows-2025-folder "$GITHUB_WORKSPACE/ops048-upstream-windows-2025" \
  --windows-2025-jsonl "$ROOT/windows-2025/result.jsonl" \
  --output "$RUNNER_TEMP/ops048-public-receipt/record-linkage.json"
printf 'PCFM_OPS048_SOURCE_CUSTODY_PRESERVED raw_evtx_or_jsonl_uploaded=false\n'
