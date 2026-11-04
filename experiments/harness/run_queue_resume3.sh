#!/usr/bin/env bash
# Resume v3 (D-040): stage 1b re-run with rate-limit backoff for Progent's gpt-4o policy calls (the first attempt
# silently skipped rate-limited policy updates), then the queue continues from stage 1c (run_queue.sh START=2).
set -u
cd "$(dirname "$0")/../.."
Q=experiments/probes/logs/queue.log
T=eval-s1b-progent-approver
echo "$(date -u +%FT%TZ) STAGE 1b RESTART $T (attempt 1 invalid: gpt-4o 429s, D-040)" >> "$Q"
G=nim:google/gemma-4-31b-it
for spec in "progent-autodeny|--progent-approver auto_deny" "progent-autoapprove|--progent-approver auto_approve" \
            "progent-manual-perfect|--progent-approver manual --sim perfect" "progent-manual-rubber|--progent-approver manual --sim rubber_stamp" \
            "progent-manual-p05|--progent-approver manual --sim plausible:0.5" "progent-manual-p09|--progent-approver manual --sim plausible:0.9"; do
  name=${spec%%|*}; extra=${spec#*|}
  TAG=$T MODEL=$G PROBE_DELAY=6 experiments/harness/pilot_lane.sh $name --defense progent $extra &
  sleep 60   # stagger starts so the policy-model calls don't arrive in one burst
done
wait
echo "$(date -u +%FT%TZ) STAGE 1b DONE $T" >> "$Q"
START=2 exec experiments/harness/run_queue.sh
