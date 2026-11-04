#!/usr/bin/env bash
# One lane of the repeats pilot: pilot_lane.sh <name> <runner args...>. Appends "<name> <run_id>" to pilot_repeats.runs.
set -u
cd "$(dirname "$0")/../.."
name=$1; shift
LOG=experiments/probes/logs/pilot_repeats
PROBE_DELAY=${PROBE_DELAY:-6} .venv/bin/python experiments/harness/runner.py --tree fc --model "${MODEL:-nim:google/gemma-4-31b-it}" \
  --attack both --repeats 3 --run-tag "${TAG:-pilot-repeats-v1}-$name" "$@" > "$LOG/${TAG:+$TAG-}$name.log" 2>&1
echo "$name $(grep -m1 "^run_id" "$LOG/${TAG:+$TAG-}$name.log" | awk '{print $2}')" >> experiments/probes/logs/${TAG:-pilot_repeats}.runs
