#!/usr/bin/env bash
# D-056 component ablations, extension of D-055 (user, 2026-11-06: "Run the extra runs: Ask-once, corroboration and
# staging under the adaptive attacks ... The ablations on a second model."). Same mechanism and settings as D-055
# (final design minus one component; fc, 3 repeats, perfect user). Also adp-no-closure, which completes the table.
#   run_d056_components.sh <tag> <nim:model> <lane> [<lane> ...]
#   gemma:    eval-d056-gemma-adp     adaptive no-askonce / no-corroboration / no-closure / no-staging
#   nemotron: eval-d056-nemotron      all D-055 lanes + the four above + adp-full (no nemotron adaptive baseline exists)
# Comparisons: gemma vs F-A5 20261012T024623Z-ac789f; nemotron main vs nemotron_new 20261012T222854Z-24d411 and
# nemotron_rope 20261007T022744Z-37cd81; nemotron adaptive vs its own adp-full lane.
set -u
cd "$(dirname "$0")/../.."
export NIM_STREAM=1 NIM_TIMEOUT=3600
Q=experiments/probes/logs/queue.log
T=$1; M=$2; shift 2; LANES="$*"
R=experiments/probes/logs/$T.runs; F=experiments/probes/logs/$T-fill.runs
NEW="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A --ceiling 500 --rel-max 0.10 --credentials never --sim perfect"
ADP="--attack vs --attack-set adaptive --max-attacks-per-task 2"
declare -A ARGS=(
  [adp-no-once]="$NEW --ablate once $ADP" [adp-no-aggregate]="$NEW --ablate aggregate $ADP"
  [adp-no-once-aggregate]="$NEW --ablate once,aggregate $ADP" [adp-no-family]="$NEW --ablate family $ADP"
  [adp-policy]="$NEW --ablate origin $ADP"
  [policy]="$NEW --ablate origin" [no-askonce]="${NEW/--unlisted ask/--unlisted deny}"
  [no-once]="$NEW --ablate once" [no-aggregate]="$NEW --ablate aggregate" [no-family]="$NEW --ablate family"
  [no-corroboration]="$NEW --ablate corroboration" [no-closure]="$NEW --ablate closure" [no-staging]="$NEW --ablate staging"
  [adp-full]="$NEW $ADP" [adp-no-askonce]="${NEW/--unlisted ask/--unlisted deny} $ADP"
  [adp-no-corroboration]="$NEW --ablate corroboration $ADP" [adp-no-closure]="$NEW --ablate closure $ADP"
  [adp-no-staging]="$NEW --ablate staging $ADP")
POOL=4
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
    if [ $rc -eq 3 ]; then log "D-056 COMPONENTS STOPPED $T: $M retired (410)"; exit 3; fi
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

log "D-056 COMPONENTS START $T ($M; $LANES)"
gate
for n in $LANES; do
  while [ "$(jobs -rp | wc -l)" -ge $POOL ]; do wait -n; done
  TAG=$T MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$n" ${ARGS[$n]} & sleep 60
done
wait; gone && { log "D-056 COMPONENTS STOPPED $T: $M retired (410)"; exit 3; }
log "D-056 COMPONENTS LANES DONE $T"
for round in 1 2 3; do
  todo=()
  for n in $LANES; do
    ep=experiments/probes/logs/$T-fill-$n-f$round.episodes
    missing $(runs_of $n) > "$ep"
    [ -s "$ep" ] && todo+=("$n") || rm -f "$ep"
  done
  [ ${#todo[@]} -eq 0 ] && break
  log "D-056 COMPONENTS FILL $T round $round: ${todo[*]}"
  gate
  for n in "${todo[@]}"; do
    while [ "$(jobs -rp | wc -l)" -ge $POOL ]; do wait -n; done
    orig=$(awk -v n=$n '$1 == n {print $2}' "$R")
    TAG=$T-fill MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$n-f$round" ${ARGS[$n]} \
      --episodes experiments/probes/logs/$T-fill-$n-f$round.episodes --fills "$orig" & sleep 60
  done
  wait; gone && { log "D-056 COMPONENTS STOPPED $T: $M retired (410)"; exit 3; }
done
for n in $LANES; do log "D-056 $T $n: $(runs_of $n | tr ' ' '+'); still missing $(missing $(runs_of $n) | grep -c .)"; done
log "D-056 COMPONENTS DONE $T"
