#!/usr/bin/env bash
# Held-out compiler items (D-033): authored blind by Codex (pinned CLI, gpt-6.1-sol) in an isolated workspace that
# holds only INSTRUCTIONS.md and the tool catalogue (no compiler prompts, no results, no benchmark prompts).
set -euo pipefail
R=<repo>; WS=<home>/ai-prov-heldout-author; OUT=$R/experiments/compiler_heldout
PINS=$R/experiments/probes/cli_pins.json
ENTRY=$(python3 -c "import json,os;print(os.path.expanduser(json.load(open('$PINS'))['codex']['entry']))")
NATIVE=$(python3 -c "import json,os;print(os.path.expanduser(json.load(open('$PINS'))['codex']['native_binary']))")
WANT=$(python3 -c "import json;print(json.load(open('$PINS'))['codex']['native_sha256'])")
[ "$(sha256sum "$NATIVE" | cut -d' ' -f1)" = "$WANT" ] || { echo "codex pin mismatch"; exit 1; }
date -u +%FT%TZ > "$OUT/author_started_utc.txt"
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY -u NVIDIA_API_KEY \
  node "$ENTRY" exec -m gpt-6.1-sol --skip-git-repo-check --ephemeral --ignore-user-config --ignore-rules \
  -s workspace-write -C "$WS" --json -c 'approval_policy="never"' \
  "Read INSTRUCTIONS.md in the current directory and carry it out fully." < /dev/null \
  > "$OUT/author_events.jsonl" 2> "$OUT/author_stderr.log" || echo "codex exit $?" >> "$OUT/author_stderr.log"
date -u +%FT%TZ > "$OUT/author_finished_utc.txt"
cp "$WS/heldout_items.jsonl" "$OUT/heldout_items.jsonl"
