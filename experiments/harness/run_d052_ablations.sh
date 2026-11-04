#!/usr/bin/env bash
# D-052 post-hoc ablations (user decision D-051, 2026-10-31: "I accept all the recommendations"; "Implement it").
# LABELLED POST-HOC: reported next to the preregistered rules, never as the headline. gemma, fc, 3 repeats, perfect user,
# new headline (D-043/D-044) plus one change each:
#   askfam-adp  : --ask-family download,web_submit on the adaptive corpus (vs F-A5 ours 20261012T024623Z-ac789f)
#   askfam-main : --ask-family download,web_submit on the main corpus, clean + v1 (vs F-32 new 20261012T024623Z-ae52ef)
#   relmax-main : --rel-mode max (max(ceiling, rel)) on the main corpus, clean + v1 (vs F-32 new)
# Error handling as stage 10 (D-049): retry budgets, health gate, 410 stop, up to 3 fill rounds (D-048 method).
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
M=nim:google/gemma-4-31b-it; T=eval-d052-ablations
R=experiments/probes/logs/$T.runs; F=experiments/probes/logs/$T-fill.runs
NEW="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A --ceiling 500 --rel-max 0.10 --credentials never --sim perfect"
ADP="--attack vs --attack-set adaptive --max-attacks-per-task 2"
declare -A ARGS=([askfam-adp]="$NEW --ask-family download,web_submit $ADP" [askfam-main]="$NEW --ask-family download,web_submit"
  [relmax-main]="$NEW --rel-mode max")
LANES="askfam-adp askfam-main relmax-main"
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
    if [ $rc -eq 3 ]; then log "D-052 ABLATIONS STOPPED: $M retired (410)"; exit 3; fi
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
runs_of() { local n=$1 r; r=$(awk -v n=$n '$1 == n {print $2}' "$R"); for f in $(awk -v n=$n '$1 ~ "^"n"-f[0-9]+$" {print $2}' "$F" 2>/dev/null); do r="$r $f"; done; echo $r; }

log "D-052 ABLATIONS START $T ($M; $LANES)"
gate
for n in $LANES; do TAG=$T MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$n" ${ARGS[$n]} & sleep 60; done
wait; gone && { log "D-052 ABLATIONS STOPPED: $M retired (410)"; exit 3; }
log "D-052 ABLATIONS LANES DONE $T"
for round in 1 2 3; do
  todo=()
  for n in $LANES; do
    ep=experiments/probes/logs/$T-fill-$n-f$round.episodes
    missing $(runs_of $n) > "$ep"
    [ -s "$ep" ] && todo+=("$n") || rm -f "$ep"
  done
  [ ${#todo[@]} -eq 0 ] && break
  log "D-052 ABLATIONS FILL round $round: ${todo[*]}"
  gate
  for n in "${todo[@]}"; do
    orig=$(awk -v n=$n '$1 == n {print $2}' "$R")
    TAG=$T-fill MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$n-f$round" ${ARGS[$n]} \
      --episodes experiments/probes/logs/$T-fill-$n-f$round.episodes --fills "$orig" & sleep 60
  done
  wait; gone && { log "D-052 ABLATIONS STOPPED: $M retired (410)"; exit 3; }
done
for n in $LANES; do log "D-052 $n: $(runs_of $n | tr ' ' '+'); still missing $(missing $(runs_of $n) | grep -c .)"; done
log "D-052 ABLATIONS DONE $T"
