#!/usr/bin/env bash
# Stage 9 fill (D-048): re-run ONLY the glm-5.3 episodes lost to NIM outages (404 outage + timeouts on CaMeL,
# 429 on the old headline; registered in INVALID.json). User instruction 2026-10-19: "re-run just the missing episodes
# (29 for the old headline, 73 for CaMeL) once glm-5.3 is reliable again".
# Same settings as the original lanes (run_stage9_glm.sh), restricted with runner --episodes; analysed as
# ORIGINAL+FILL[+FILL] (analyze_repeats.load). Waits for the paused old-headline lane to finish, gates on glm-5.3
# answering 3 probes in a row 5 min apart, and does up to 3 rounds (each round re-runs what is still missing).
# Progress: experiments/probes/logs/queue.log; run IDs: experiments/probes/logs/eval-s9-glm53-fill.runs.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log; R=experiments/probes/logs/eval-s9-glm53.runs; F=experiments/probes/logs/eval-s9-glm53-fill.runs
M=nim:z-ai/glm-5.3; T=eval-s9-glm53-fill
OLD="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A --ceiling 500"
log() { echo "$(date -u +%FT%TZ) $*" >> "$Q"; }
probe() {
  .venv/bin/python - <<'PY'
import re, sys, openai
key = next(re.match(r'\s*(?:export\s+)?NVIDIA_API_KEY\s*=\s*"?([^"\n]+)"?', l).group(1) for l in open(".env") if "NVIDIA_API_KEY" in l)
c = openai.OpenAI(api_key=key, base_url="https://integrate.api.nvidia.com/v1", max_retries=0, timeout=120)
try: c.chat.completions.create(model="z-ai/glm-5.3", messages=[{"role": "user", "content": "Say OK."}], max_tokens=5)
except Exception: sys.exit(1)
PY
}
gate() { local ok=0; until [ $ok -ge 3 ]; do if probe; then ok=$((ok + 1)); else ok=0; fi; [ $ok -ge 3 ] || sleep 300; done; }
# Episodes of the condition that still have no valid record (errored in every run so far; ROPE-style "n/a" excluded).
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

# Restart (D-048): NAMES, ROUNDS (round labels) and PRIOR (fill runs already done, "+RUN...") resume one lane, e.g.
#   NAMES=camel ROUNDS="2 3 4" PRIOR=+20261019T221529Z-89db2f NIM_TIMEOUT=1200 run_stage9_fill.sh
# LANES=N splits each round's episodes into N parallel lanes (<name>-r<round><k>; user instruction 2026-10-25).
until grep -q "^bllm-ask-perfect " "$R" 2>/dev/null; do sleep 600; done
log "STAGE 9 FILL START $T${NAMES:+ ($NAMES, rounds ${ROUNDS:-1 2 3}, NIM_TIMEOUT ${NIM_TIMEOUT:-300})}"
for name in ${NAMES:-bllm-ask-perfect camel}; do
  orig=$(awk -v n=$name '$1 == n {print $2}' "$R")
  case $name in bllm-ask-perfect) args="$OLD --sim perfect" ;; camel) args="--defense camel" ;; esac
  runs=$orig${PRIOR:-}
  for round in ${ROUNDS:-1 2 3}; do
    ep=experiments/probes/logs/$T-$name-r$round.episodes
    missing ${runs//+/ } > "$ep"
    [ -s "$ep" ] || break
    gate
    log "STAGE 9 FILL $name round $round: $(wc -l < "$ep") episodes in ${LANES:-1} lane(s) (fills $orig)"
    if [ "${LANES:-1}" -le 1 ]; then lanes="$name-r$round"; cp "$ep" "$ep.$name-r$round"
    else  # LANES>1: contiguous chunks of the episode list, one pilot_lane each (same settings; 429s: retry.with_retry)
      split -n l/"$LANES" -d -a 1 "$ep" "$ep.part"; lanes=""
      for c in "$ep".part*; do l=$name-r$round${c##*.part}; mv "$c" "$ep.$l"; lanes="$lanes $l"; done; fi
    for l in $lanes; do
      TAG=$T MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$l" $args --episodes "$ep.$l" --fills "$orig" &
      sleep 60; done  # staggered starts
    wait
    for l in $lanes; do runs="$runs+$(awk -v n=$l '$1 == n {print $2}' "$F")"; done
  done
  log "STAGE 9 FILL $name: $runs; still missing $(missing ${runs//+/ } | grep -c .)"
done
log "STAGE 9 FILL DONE $T"
