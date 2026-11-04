#!/usr/bin/env bash
# Repeated-runs pilot (F-09, D-025 main condition = no user turns): main stratum (30 evaluable tasks), clean + 1
# value-substitution attack per task, 3 repeats, one NIM model, five defense conditions. Run IDs are appended to
# experiments/probes/logs/pilot_repeats.runs (one line per condition).
set -u
cd "$(dirname "$0")/../.."
MODEL=${MODEL:-nim:google/gemma-4-31b-it}
TAG=${TAG:-pilot-repeats-v1}
LOG=experiments/probes/logs/pilot_repeats
mkdir -p "$LOG"
run() {  # name, args...
  local name=$1; shift
  PROBE_DELAY=${PROBE_DELAY:-4} .venv/bin/python experiments/harness/runner.py --tree fc --model "$MODEL" --attack both \
    --repeats 3 --run-tag "$TAG-$name" "$@" > "$LOG/$name.log" 2>&1
  echo "$name $(grep '^run_id' "$LOG/$name.log" | awk '{print $2}')" >> experiments/probes/logs/pilot_repeats.runs
}
# two lanes in parallel (NIM 403s on wider bursts, see model-inventory); same model in both
( run none --defense none
  run bounded-oracle-A500 --defense bounded --compiler oracle --mode A --ceiling 500
  run progent --defense progent ) &
( run bounded-llm-A500 --defense bounded --compiler llm --mode A --ceiling 500
  run rope --defense rope ) &
wait
echo ALLDONE >> experiments/probes/logs/pilot_repeats.runs
