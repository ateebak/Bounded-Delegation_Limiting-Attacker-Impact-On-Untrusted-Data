#!/usr/bin/env bash
# Third lane of the repeats pilot: bounded-llm-A500, relaunched after the D-028 simulator fix.
set -u
cd "$(dirname "$0")/../.."
LOG=experiments/probes/logs/pilot_repeats
PROBE_DELAY=6 .venv/bin/python experiments/harness/runner.py --tree fc --model nim:google/gemma-4-31b-it --attack both \
  --repeats 3 --run-tag pilot-repeats-v1-bounded-llm-A500 --defense bounded --compiler llm --mode A --ceiling 500 > "$LOG/bounded-llm-A500.log" 2>&1
echo "bounded-llm-A500 $(grep '^run_id' "$LOG/bounded-llm-A500.log" | awk '{print $2}')" >> experiments/probes/logs/pilot_repeats.runs
echo LANE3DONE >> experiments/probes/logs/pilot_repeats.runs
