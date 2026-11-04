#!/usr/bin/env bash
# Resume of the evaluation queue (D-038): the original controller was stopped mid-stage-1 (its lanes kept running) so
# that stage 1b (Progent + our v3-style approver) could be inserted before stage 2. Waits for the stage-1 lanes, logs
# STAGE 1 DONE, runs stage 1b, then continues run_queue.sh from stage 2.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
while ps -eo args | grep "harness/runner.py" | grep -v grep | grep -q "run-tag eval-s1-"; do sleep 120; done
sleep 30  # let the lane wrappers append their run IDs
echo "$(date -u +%FT%TZ) STAGE 1 DONE eval-s1" >> "$Q"
T=eval-s1b-progent-approver
echo "$(date -u +%FT%TZ) STAGE 1b START $T" >> "$Q"
G=nim:google/gemma-4-31b-it
for spec in "progent-autodeny|--progent-approver auto_deny" "progent-autoapprove|--progent-approver auto_approve" \
            "progent-manual-perfect|--progent-approver manual --sim perfect" "progent-manual-rubber|--progent-approver manual --sim rubber_stamp" \
            "progent-manual-p05|--progent-approver manual --sim plausible:0.5" "progent-manual-p09|--progent-approver manual --sim plausible:0.9"; do
  name=${spec%%|*}; extra=${spec#*|}
  TAG=$T MODEL=$G PROBE_DELAY=6 experiments/harness/pilot_lane.sh $name --defense progent $extra &
done
wait
echo "$(date -u +%FT%TZ) STAGE 1b DONE $T" >> "$Q"
START=2 exec experiments/harness/run_queue.sh
