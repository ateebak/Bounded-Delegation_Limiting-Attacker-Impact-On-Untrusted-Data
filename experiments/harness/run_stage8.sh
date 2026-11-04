#!/usr/bin/env bash
# Stage 8 (D-046): relative caps (D-043) + never-delegable credentials (D-044) + adaptive attack set (D-045).
# User instruction 2026-10-11: "Do 1 and 2 and then 3. Try to see if stage 5 can be run".
# Progress: experiments/probes/logs/queue.log. Run IDs: experiments/probes/logs/<TAG>.runs.
# Parts: PARTS="8a 8b 8c 5" (default all, in order). 8a = gemma lanes; 8b = replication of the new headline on
# nemotron + API models; 8c = adaptive set on the API models' new headline; 5 = deepseek (gated) with the new headline.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
NEW="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A --ceiling 500 --rel-max 0.10 --credentials never"
ORC="--defense bounded --compiler oracle --unlisted ask --caps hard --mode A --ceiling 500 --rel-max 0.10 --credentials never"
ADP="--attack vs --attack-set adaptive --max-attacks-per-task 2"
AV2="--attack vs --attack-set authored-v2"
GEMMA=nim:google/gemma-4-31b-it
PARTS=${PARTS:-"8a 8b 8c 5"}

lane() { local tag=$1 model=$2 name=$3; shift 3
  TAG=$tag MODEL=$model PROBE_DELAY=${PROBE_DELAY:-6} experiments/harness/pilot_lane.sh "$name" "$@" & }
log() { echo "$(date -u +%FT%TZ) $*" >> "$Q"; }
nim_up() {
  .venv/bin/python - "$1" <<'PY'
import re, sys, openai
key = next(re.match(r'\s*(?:export\s+)?NVIDIA_API_KEY\s*=\s*"?([^"\n]+)"?', l).group(1) for l in open(".env") if "NVIDIA_API_KEY" in l)
c = openai.OpenAI(api_key=key, base_url="https://integrate.api.nvidia.com/v1", max_retries=0, timeout=120)
for _ in range(2):
    try:
        c.chat.completions.create(model=sys.argv[1].split(":", 1)[1], messages=[{"role": "user", "content": "Say OK."}], max_tokens=5)
        sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PY
}

for part in $PARTS; do case $part in
8a) T=eval-s8-relcred; log "STAGE 8a START $T"
  lane $T $GEMMA new-perfect   $NEW --sim perfect
  lane $T $GEMMA new-rubber    $NEW --sim rubber_stamp
  lane $T $GEMMA orc-perfect   $ORC --sim perfect
  lane $T $GEMMA av2-new       $NEW --sim perfect $AV2
  lane $T $GEMMA av2-orc       $ORC --sim perfect $AV2
  lane $T $GEMMA adp-new       $NEW --sim perfect $ADP
  wait
  lane $T $GEMMA adp-new-rubber $NEW --sim rubber_stamp $ADP
  lane $T $GEMMA adp-none      --defense none $ADP
  lane $T $GEMMA adp-rope      --defense rope $ADP
  lane $T $GEMMA adp-progent   --defense progent $ADP
  lane $T $GEMMA adp-drift     --defense drift $ADP
  wait; log "STAGE 8a DONE $T" ;;
8b) T=eval-s8-replicate; log "STAGE 8b START $T"
  lane $T nim:nvidia/nemotron-3.5-lightning-30b-a3b nemotron-new $NEW --sim perfect
  PROBE_DELAY=0 lane $T anthropic:claude-sonnet-5-5 sonnet-new $NEW --sim perfect
  PROBE_DELAY=0 lane $T openai:gpt-6.1-sol gpt61-new $NEW --sim perfect
  wait; log "STAGE 8b DONE $T" ;;
8c) T=eval-s8-adaptive-api; log "STAGE 8c START $T"
  PROBE_DELAY=0 lane $T anthropic:claude-sonnet-5-5 sonnet-adp-new $NEW --sim perfect $ADP
  PROBE_DELAY=0 lane $T openai:gpt-6.1-sol gpt61-adp-new $NEW --sim perfect $ADP
  wait; log "STAGE 8c DONE $T" ;;
5) M=nim:deepseek-ai/deepseek-v4.1-flash; T=eval-s5b-deepseek
  if nim_up "$M"; then log "STAGE 5 START $T"
    lane $T $M none --defense none; lane $T $M rope --defense rope; lane $T $M new-perfect $NEW --sim perfect
    wait
    lane $T $M progent --defense progent; lane $T $M drift --defense drift; lane $T $M camel --defense camel
    wait; log "STAGE 5 DONE $T"
  else log "STAGE 5 SKIPPED $T (NIM endpoint unavailable)"; fi ;;
esac; done
log "STAGE8 QUEUE DONE"
