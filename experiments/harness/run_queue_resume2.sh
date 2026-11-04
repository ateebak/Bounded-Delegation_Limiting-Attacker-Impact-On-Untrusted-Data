#!/usr/bin/env bash
# Resume v2 (D-038 follow-up): the CaMeL lane is far slower than the rest of stage 1, so stage 1b starts as soon as
# every stage-1 lane EXCEPT CaMeL has finished, running alongside it (7 NIM lanes, as in stage 1). Stage 1 is logged
# DONE when CaMeL finishes; stage 2 starts only after both stage 1 and stage 1b are done.
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
running() { ps -eo args | grep "harness/runner.py" | grep -v grep | grep -o "run-tag [^ ]*" | awk '{print $2}'; }
while running | grep "^eval-s1-" | grep -vq "^eval-s1-camel$"; do sleep 120; done
T=eval-s1b-progent-approver
echo "$(date -u +%FT%TZ) STAGE 1b START $T" >> "$Q"
G=nim:google/gemma-4-31b-it
for spec in "progent-autodeny|--progent-approver auto_deny" "progent-autoapprove|--progent-approver auto_approve" \
            "progent-manual-perfect|--progent-approver manual --sim perfect" "progent-manual-rubber|--progent-approver manual --sim rubber_stamp" \
            "progent-manual-p05|--progent-approver manual --sim plausible:0.5" "progent-manual-p09|--progent-approver manual --sim plausible:0.9"; do
  name=${spec%%|*}; extra=${spec#*|}
  TAG=$T MODEL=$G PROBE_DELAY=6 experiments/harness/pilot_lane.sh $name --defense progent $extra &
done
( while running | grep -q "^eval-s1-camel$"; do sleep 120; done; sleep 30
  echo "$(date -u +%FT%TZ) STAGE 1 DONE eval-s1" >> "$Q" ) &
wait
echo "$(date -u +%FT%TZ) STAGE 1b DONE $T" >> "$Q"
START=2 exec experiments/harness/run_queue.sh
