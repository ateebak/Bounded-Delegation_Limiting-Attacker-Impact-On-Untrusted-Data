"""Verify that every user-task prompt still hits ROPE's cached router scopes after fixture correction (D-015).

  PYTHONPATH=<tree>/autodojo/src .venv/bin/python experiments/fixtures/check_rope_scope_cache.py <tree> <label>
Reports, per router and suite, how many user-task prompts have a cached scope. The fixture_corrected tree
must hit exactly as often as the original (a miss makes ROPE block every state-changing tool).
"""
import json, pathlib, sys
from agentdojo.task_suite.load_suites import get_suites

tree, label = pathlib.Path(sys.argv[1]), sys.argv[2]
out = {}
for router_dir in sorted((tree / "src/rope/scopes").iterdir()):
    if router_dir.name.startswith("_"): continue
    for sf in sorted(router_dir.glob("*.json")):
        scopes = json.loads(sf.read_text())
        suite = get_suites("v1.2.2")[sf.stem]
        prompts = [t.PROMPT for t in suite.user_tasks.values()]
        hits = sum(p in scopes for p in prompts)
        out[f"{router_dir.name}/{sf.stem}"] = {"prompts": len(prompts), "hits": hits, "misses": [p[:70] for p in prompts if p not in scopes]}
        print(f"{label:17s} {router_dir.name:15s} {sf.stem:10s} {hits}/{len(prompts)}")
(pathlib.Path(__file__).resolve().parent / f"rope_scope_cache_{label}.json").write_text(json.dumps(out, indent=1) + "\n")
