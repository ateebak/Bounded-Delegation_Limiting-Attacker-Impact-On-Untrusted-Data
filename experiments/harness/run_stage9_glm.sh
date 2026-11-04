#!/usr/bin/env bash
# Stage 9 (D-047): glm-5.3 (non-flash) as the sixth model, replacing the unusable glm-5.3-flash (F-31) and deepseek
# (F-31; 244 s first-token latency on 2026-10-12). User instruction 2026-10-12: "Glm-5.3 would work for a sixth model".
# Same lanes as the other NIM model stages (D-042: waves of 3), plus the D-043/D-044 headline and the old hard-cap
# headline, so glm-5.3 joins both the F-30 table and the stage-8 replication. Runs alongside stage 8 (different NIM
# model, so separate per-model rate limits). Progress: experiments/probes/logs/queue.log.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
M=nim:z-ai/glm-5.3; T=eval-s9-glm53
OLD="--defense bounded --compiler llm --compiler-prompt v2 --unlisted ask --caps hard --mode A --ceiling 500"
NEW="$OLD --rel-max 0.10 --credentials never"
lane() { local name=$1; shift; TAG=$T MODEL=$M PROBE_DELAY=6 experiments/harness/pilot_lane.sh "$name" "$@" & }
echo "$(date -u +%FT%TZ) STAGE 9 START $T" >> "$Q"
lane none --defense none; lane rope --defense rope; lane new-perfect $NEW --sim perfect
wait
lane progent --defense progent; lane drift --defense drift; lane camel --defense camel
wait
lane bllm-ask-perfect $OLD --sim perfect
wait
echo "$(date -u +%FT%TZ) STAGE 9 DONE $T" >> "$Q"
