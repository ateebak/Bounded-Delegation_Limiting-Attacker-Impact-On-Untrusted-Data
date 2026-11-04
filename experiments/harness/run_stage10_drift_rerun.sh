#!/usr/bin/env bash
# Stage 10 DRIFT re-run (D-050): the original DRIFT lane (20261030T101842Z-5195df) lost MiniMax's native tool calls in
# DRIFT's parser and is registered invalid; this re-runs it with the extended native-call shim. User approval
# 2026-10-31 ("Re-run DRIFT"). Same settings and error handling as run_stage10_minimax.sh (D-049): streaming, retry
# budgets, health gate, 410 stop, up to 3 fill rounds (D-048 method, analysed as ORIGINAL+FILL).
# Runs: experiments/probes/logs/eval-s10-minimax-rerun.runs; fills: eval-s10-minimax-rerun-fill.runs.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
M=nim:minimaxai/minimax-m3.1-flash; T=eval-s10-minimax-rerun
R=experiments/probes/logs/$T.runs; F=experiments/probes/logs/$T-fill.runs
export NIM_STREAM=1 NIM_TIMEOUT=3600
log() { echo "$(date -u +%FT%TZ) $*" >> "$Q"; }
probe() {
  .venv/bin/python - "${M#nim:}" <<'PY'
import re, sys, openai
key = next(re.match(r'\s*(?:export\s+)?NVIDIA_API_KEY\s*=\s*"?([^"\n]+)"?', l).group(1) for l in open(".env") if "NVIDIA_API_KEY" in l)
c = openai.OpenAI(api_key=key, base_url="https://integrate.api.nvidia.com/v1", max_retries=0, timeout=120)
try: c.chat.completions.create(model=sys.argv[1], messages=[{"role": "user", "content": "Say OK."}], max_tokens=20)
except Exception as e: sys.exit(3 if "Error code: 410" in str(e) else 1)
PY
}
gate() {
  local ok=0 rc
  until [ $ok -ge 3 ]; do
    probe; rc=$?
    if [ $rc -eq 3 ]; then log "STAGE 10 DRIFT RERUN STOPPED: $M retired (410)"; exit 3; fi
    if [ $rc -eq 0 ]; then ok=$((ok + 1)); else ok=0; fi
    [ $ok -ge 3 ] || sleep 300
  done
}
gone() { grep -q "Error code: 410" experiments/probes/logs/pilot_repeats/$T-*.log 2>/dev/null; }
missing() {
  .venv/bin/python - "$@" <<'PY'
import json, pathlib, sys
best = {}
for rid in sys.argv[1:]:
    for f in pathlib.Path("experiments/runs", rid).glob("*__*.json"):
        r = json.loads(f.read_text()); err = r.get("error") or ""
        if err.startswith("n/a"): continue
        best[r["episode"]] = best.get(r["episode"], False) or not err
out = sorted(e for e, ok in best.items() if not ok)
if out: print("\n".join(out))
PY
}
runs() { echo $(awk '$1 == "drift" {print $2}' "$R") $(awk '$1 ~ /^drift-f[0-9]+$/ {print $2}' "$F" 2>/dev/null); }

log "STAGE 10 DRIFT RERUN START $T ($M; D-050 shim)"
gate
TAG=$T MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh drift --defense drift
gone && { log "STAGE 10 DRIFT RERUN STOPPED: $M retired (410)"; exit 3; }
orig=$(awk '$1 == "drift" {print $2}' "$R")
for round in 1 2 3; do
  ep=experiments/probes/logs/$T-fill-drift-f$round.episodes
  missing $(runs) > "$ep"
  [ -s "$ep" ] || { rm -f "$ep"; break; }
  log "STAGE 10 DRIFT RERUN fill round $round: $(wc -l < "$ep") episodes"
  gate
  TAG=$T-fill MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "drift-f$round" --defense drift --episodes "$ep" --fills "$orig"
  gone && { log "STAGE 10 DRIFT RERUN STOPPED: $M retired (410)"; exit 3; }
done
log "STAGE 10 DRIFT RERUN drift: $(runs | tr ' ' '+'); still missing $(missing $(runs) | grep -c .)"
log "STAGE 10 DRIFT RERUN DONE $T"
