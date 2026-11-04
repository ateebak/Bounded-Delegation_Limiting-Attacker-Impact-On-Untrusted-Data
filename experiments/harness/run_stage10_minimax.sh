#!/usr/bin/env bash
# Stage 10 (D-049): minimax-m3.1-flash as the sixth model, replacing glm-5.3 (NIM retired it 2026-10-28T08:00Z, 410 Gone).
# User instruction 2026-10-29: "Yes launch the full MiniMax stage as the sixth model. Make sure we have retries and
# backoffs and error handling."
# Same lanes and settings as stage 9 (run_stage9_glm.sh), waves of 3 (D-042). Error handling (D-048, D-049):
#   - streamed NIM responses (NIM_STREAM=1; no gateway 504s), client timeout 3600 s;
#   - retry.with_retry: 7 tries with backoff for 5xx/404/timeouts/connection errors/cut-off streams/empty choices;
#     429s have their own 6 h budget with jitter and Retry-After;
#   - 410 (model retired) stops a lane at once (runner exits 3) and this script stops;
#   - health gate before each wave and fill round: 3 answered probes in a row, 5 min apart;
#   - fill rounds (D-048 method): up to 3 rounds re-run every episode that still has no valid record, as
#     <lane>-f<round> with --fills <original run>; analysed as ORIGINAL+FILL.
# Progress: experiments/probes/logs/queue.log; runs: eval-s10-minimax.runs; fills: eval-s10-minimax-fill.runs.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
M=nim:minimaxai/minimax-m3.1-flash; T=eval-s10-minimax
R=experiments/probes/logs/$T.runs; F=experiments/probes/logs/$T-fill.runs
export NIM_STREAM=1 NIM_TIMEOUT=3600
OLD="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A --ceiling 500"
NEW="$OLD --rel-max 0.10 --credentials never"
declare -A ARGS=([none]="--defense none" [rope]="--defense rope" [new-perfect]="$NEW --sim perfect"
  [progent]="--defense progent" [drift]="--defense drift" [camel]="--defense camel" [bllm-ask-perfect]="$OLD --sim perfect")
log() { echo "$(date -u +%FT%TZ) $*" >> "$Q"; }
probe() {  # 0 = answered, 1 = failed, 3 = model gone (410)
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
    if [ $rc -eq 3 ]; then log "STAGE 10 STOPPED $T: $M retired (410)"; exit 3; fi
    if [ $rc -eq 0 ]; then ok=$((ok + 1)); else ok=0; fi
    [ $ok -ge 3 ] || sleep 300
  done
}
gone() { grep -q "Error code: 410" experiments/probes/logs/pilot_repeats/$T-*.log 2>/dev/null; }
# Episodes with no valid record across the given runs ("n/a" baseline markers excluded).
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
runs_of() { local n=$1 r; r=$(awk -v n=$n '$1 == n {print $2}' "$R"); for f in $(awk -v n=$n '$1 ~ "^"n"-f[0-9]+$" {print $2}' "$F" 2>/dev/null); do r="$r $f"; done; echo $r; }
lane() { local name=$1; TAG=$T MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$name" ${ARGS[$name]} & sleep 60; }
wave() { gate; for n in "$@"; do lane $n; done; wait; gone && { log "STAGE 10 STOPPED $T: $M retired (410)"; exit 3; }; }

log "STAGE 10 START $T ($M; NIM_STREAM=1, NIM_TIMEOUT=3600)"
wave none rope new-perfect
wave progent drift camel
wave bllm-ask-perfect
log "STAGE 10 LANES DONE $T"

for round in 1 2 3; do
  todo=()
  for n in none rope new-perfect progent drift camel bllm-ask-perfect; do
    ep=experiments/probes/logs/$T-fill-$n-f$round.episodes
    missing $(runs_of $n) > "$ep"
    [ -s "$ep" ] && todo+=("$n") || rm -f "$ep"
  done
  [ ${#todo[@]} -eq 0 ] && break
  log "STAGE 10 FILL round $round: ${todo[*]}"
  for ((i = 0; i < ${#todo[@]}; i += 3)); do
    gate
    for n in "${todo[@]:i:3}"; do
      orig=$(awk -v n=$n '$1 == n {print $2}' "$R")
      TAG=$T-fill MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$n-f$round" ${ARGS[$n]} \
        --episodes experiments/probes/logs/$T-fill-$n-f$round.episodes --fills "$orig" & sleep 60
    done
    wait; gone && { log "STAGE 10 STOPPED $T: $M retired (410)"; exit 3; }
  done
done
for n in none rope new-perfect progent drift camel bllm-ask-perfect; do
  log "STAGE 10 $n: $(runs_of $n | tr ' ' '+'); still missing $(missing $(runs_of $n) | grep -c .)"
done
log "STAGE 10 DONE $T"
