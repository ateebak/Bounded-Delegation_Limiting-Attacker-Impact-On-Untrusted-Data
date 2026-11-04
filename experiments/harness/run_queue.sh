#!/usr/bin/env bash
# Evaluation queue after the pilot (user instruction 2026-10-04: "Do 1 and 3 together, then queue the rest"; D-037).
# Stages run one after another; the lanes inside a stage run in parallel (pilot_lane.sh: fc tree, main stratum,
# clean + 1 v1 attack, 3 repeats unless a lane overrides). Progress: experiments/probes/logs/queue.log.
# Each stage writes run IDs to experiments/probes/logs/<TAG>.runs. Resume a stage: START=<stage> run_queue.sh.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
HEAD="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A"   # headline (D-034/D-035/D-039)
ORC="--defense bounded --compiler oracle --unlisted ask --caps hard --mode A"
START=${START:-1}
# D-042: STAGES lists the model stages (4-7) to run, in order, after the fixed stages up to 3. NIM model stages are
# gated by an availability probe; an unavailable endpoint is logged as SKIPPED instead of producing failed runs.
STAGES=${STAGES:-"4 5 6 7"}

nim_up() {  # model -> 0 if the NIM endpoint answers a trivial request within 120 s (two tries)
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

lane() {  # tag model name args...
  local tag=$1 model=$2 name=$3; shift 3
  TAG=$tag MODEL=$model PROBE_DELAY=${PROBE_DELAY:-6} experiments/harness/pilot_lane.sh "$name" "$@" &
}
stage() {  # n tag
  echo "$(date -u +%FT%TZ) STAGE $1 START $2" >> "$Q"
}
done_stage() {
  wait
  echo "$(date -u +%FT%TZ) STAGE $1 DONE $2" >> "$Q"
}

GEMMA=nim:google/gemma-4-31b-it

if [ "$START" -le 1 ]; then  # (1) simulated-user sweep + (3) DRIFT/CaMeL
  T=eval-s1; stage 1 $T
  lane $T $GEMMA bllm-ask-perfect  $HEAD --ceiling 500 --sim perfect
  lane $T $GEMMA bllm-ask-rubber   $HEAD --ceiling 500 --sim rubber_stamp
  lane $T $GEMMA bllm-ask-p05      $HEAD --ceiling 500 --sim plausible:0.5
  lane $T $GEMMA bllm-ask-p09      $HEAD --ceiling 500 --sim plausible:0.9
  lane $T $GEMMA borc-ask-perfect  $ORC  --ceiling 500 --sim perfect
  lane $T $GEMMA drift             --defense drift
  lane $T $GEMMA camel             --defense camel
  done_stage 1 $T
fi

if [ "$START" -le 2 ]; then  # (1c) simulated-user sweep again with HARD caps (D-039); stage 1 used soft caps
  T=eval-s1c-hardcaps; stage 1c $T
  for sim in perfect rubber_stamp plausible:0.5 plausible:0.9; do
    n=${sim/plausible:/p}; n=${n/./}; n=${n/rubber_stamp/rubber}
    lane $T $GEMMA bllm-ask-$n $HEAD --ceiling 500 --sim $sim
  done
  lane $T $GEMMA borc-ask-perfect $ORC --ceiling 500 --sim perfect
  done_stage 1c $T
fi

if [ "$START" -le 2 ]; then  # (2) ceiling sweep + mode B, headline (hard caps), perfect user (500 = stage 1c)
  T=eval-s2; stage 2 $T
  for c in 100 250 1000 none; do lane $T $GEMMA bllm-ask-c$c $HEAD --ceiling $c --sim perfect; done
  lane $T $GEMMA bllm-ask-modeB --defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode B --ceiling 500 --sim perfect
  done_stage 2 $T
fi

if [ "$START" -le 3 ]; then  # (4) authored attack set v2: SEPARATE corpus (D-029), attack episodes only
  T=eval-s3-authored-v2; stage 3 $T
  AV="--attack vs --attack-set authored-v2"
  lane $T $GEMMA none      --defense none $AV
  lane $T $GEMMA rope      --defense rope $AV
  lane $T $GEMMA progent   --defense progent $AV
  lane $T $GEMMA drift     --defense drift $AV
  lane $T $GEMMA camel     --defense camel $AV
  lane $T $GEMMA bllm-ask-perfect $HEAD --ceiling 500 --sim perfect $AV
  lane $T $GEMMA borc-ask-perfect $ORC  --ceiling 500 --sim perfect $AV
  done_stage 3 $T
fi

models_stage() {  # n model short. D-042: two waves of 3 lanes (NIM per-model rate limits; stage 4 attempt 1 failed at 6)
  local T=eval-s$1-$3; stage $1 $T
  lane $T $2 none    --defense none
  lane $T $2 rope    --defense rope
  lane $T $2 bllm-ask-perfect $HEAD --ceiling 500 --sim perfect
  wait
  lane $T $2 progent --defense progent
  lane $T $2 drift   --defense drift
  lane $T $2 camel   --defense camel
  done_stage $1 $T
}
api_stage() {  # (5) frontier API models (budget-guarded, D-014); both in parallel
  local T=eval-s7-api; stage 7 $T
  for M in anthropic:claude-sonnet-5-5 openai:gpt-6.1-sol; do
    s=${M#*:}; s=${s%%-5-5}; s=${s%%.1-sol}
    PROBE_DELAY=0 lane $T $M ${s}-none    --defense none
    PROBE_DELAY=0 lane $T $M ${s}-rope    --defense rope
    PROBE_DELAY=0 lane $T $M ${s}-progent --defense progent
    PROBE_DELAY=0 lane $T $M ${s}-camel   --defense camel
    PROBE_DELAY=0 lane $T $M ${s}-bllm-ask-perfect $HEAD --ceiling 500 --sim perfect
  done
  done_stage 7 $T
}
for st in $STAGES; do
  case $st in
    4) M=nim:nvidia/nemotron-3.5-lightning-30b-a3b; short=nemotron ;;
    5) M=nim:deepseek-ai/deepseek-v4.1-flash; short=deepseek ;;
    6) M=nim:z-ai/glm-5.3-flash; short=glm ;;
    7) api_stage; continue ;;
  esac
  if nim_up "$M"; then models_stage $st "$M" $short
  else echo "$(date -u +%FT%TZ) STAGE $st SKIPPED eval-s$st-$short (NIM endpoint unavailable)" >> "$Q"; fi
done
echo "$(date -u +%FT%TZ) QUEUE DONE" >> "$Q"
