"""Score the model-based envelope compiler against gold delegation labels (no agent runs; compiler only).

For each task: gold delegated sensitive fields (same rule as compile_envelope oracle) vs LLM-proposed fields.
Reports per-task TP/FP/FN, micro precision/recall, and corroboration agreement. Over-delegation (FP) widens the
attack surface; under-delegation (FN) costs utility (the field falls back to the floor).
  PYTHONPATH=external/AgentDyn/src:. .venv/bin/python experiments/harness/compiler_accuracy.py [--compiler-model anthropic:claude-sonnet-5-5] [--substratum main]
"""
import argparse, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "external/ROPE-fc/autodojo/src"), str(ROOT), str(ROOT / "experiments/harness"), str(ROOT / "experiments/extensions"), str(ROOT / "experiments/costs")]
import ledger
from compile_llm import cached_complete
from defense.bounded.envelope import compile_envelope, TABLE

ap = argparse.ArgumentParser()
ap.add_argument("--compiler-model", default="anthropic:claude-sonnet-5-5")
ap.add_argument("--substratum", default="all", help="main | local_record | ... | all (non-excluded)")
ap.add_argument("--prompt-version", default="v2", choices=["v1", "v2", "v3"])
ap.add_argument("--set", default="dev", choices=["dev", "heldout", "heldout_authored"],
                help="dev = the 55 gold tasks (prompts were revised on these); heldout = the 74 non-gold tasks with SILVER "
                     "labels from the stratum screen (field delegated iff its value traces to attacker-writable content)")
a = ap.parse_args()

from agentdojo.task_suite.load_suites import get_suites
from ext_tasks import TASKS as EXT
suites = get_suites("v1.2.2")
ANN = ROOT / "experiments/stratum/annotations"
gold = {}
for d in ("gold_pilot_v04", "gold_v04"):
    for f in (ANN / d).glob("*__*.json"):
        r = json.loads(f.read_text()); gold[r["task_key"]] = r
keys = sorted(k for k, r in gold.items() if r.get("substratum") not in (None, "excluded") and (a.substratum == "all" or r.get("substratum") == a.substratum))
if a.set == "heldout":  # silver labels in the gold record format, so compile_envelope applies identical expansions
    import csv
    silver = {}
    for r in csv.DictReader(open(ROOT / "experiments/stratum/delegated_candidates_args.csv")):
        k = f"{r['suite']}__{r['task']}"
        if k in gold: continue
        silver.setdefault(k, {"task_key": k, "substratum": "silver", "fields": []})
        if r["tool"] in TABLE and r["arg"] in TABLE[r["tool"]] and ("attacker_only" in r["origin"] or "mixed" in r["origin"]):
            silver[k]["fields"].append({"call": r["tool"], "arg": r["arg"], "delegation_explicitness": "silver",
                                        "attacker_can_write_value": "yes", "trusted_corroboration_available": "no"})
    gold = silver; keys = sorted(silver)
AUTHORED = {}
if a.set == "heldout_authored":  # D-033: Codex-authored request-level items, labels checked by a second model
    for l in open(ROOT / "experiments/compiler_heldout/heldout_verified.jsonl"):
        it = json.loads(l)
        AUTHORED[it["id"]] = it
    gold = {k: {"task_key": k, "substratum": it["kind"], "fields": [
        {"call": d["tool"], "arg": d["arg"], "delegation_explicitness": "authored", "attacker_can_write_value": "yes",
         "trusted_corroboration_available": "no"} for d in it["delegated"]]} for k, it in AUTHORED.items()}
    keys = sorted(gold)
ctx = {"ledger_id": f"compiler-accuracy/{a.compiler_model}"}
comp = cached_complete(a.compiler_model, ctx)
rows, TP, FP, FN, corr_agree, corr_n = [], 0, 0, 0, 0, 0
for k in keys:
    if k in AUTHORED:
        suite_name, prompt = AUTHORED[k]["suite"], AUTHORED[k]["request"]
    elif "_ext" in k.split("__")[1]:
        suite_name, tid = k.split("__")
        t = next(t for t in EXT if k == f"{t.suite}__{t.id.replace(f'ext_{t.suite}_', 'user_task_ext')}")
        prompt = t.prompt
    else:
        suite_name, tid = k.split("__")
        prompt = suites[suite_name].user_tasks[tid].PROMPT
    tools = [f.name for f in suites[suite_name].tools]
    docs = {f.name: f.description for f in suites[suite_name].tools}
    ge = compile_envelope(prompt, compiler="oracle", gold=gold[k])
    le = compile_envelope(prompt, compiler="llm", tools=tools, llm_complete=comp, tool_docs=docs, prompt_version=a.prompt_version)
    gs, ls = set(ge.fields), set(le.fields)
    tp, fp, fn = gs & ls, ls - gs, gs - ls
    TP, FP, FN = TP + len(tp), FP + len(fp), FN + len(fn)
    for f in tp:
        if ge.fields[f].role == "destination":
            corr_n += 1; corr_agree += ge.fields[f].corroborate == le.fields[f].corroborate
    rows.append({"task": k, "substratum": gold[k].get("substratum"), "tp": sorted(map(".".join, tp)), "fp": sorted(map(".".join, fp)),
                 "fn": sorted(map(".".join, fn)), "compile_error": le.compile_error})
P = TP / (TP + FP) if TP + FP else float("nan"); R = TP / (TP + FN) if TP + FN else float("nan")
res = {"compiler_model": a.compiler_model, "prompt_version": a.prompt_version, "set": a.set, "n_tasks": len(keys), "TP": TP, "FP": FP, "FN": FN, "precision": round(P, 3), "recall": round(R, 3),
       "f1": round(2 * P * R / (P + R), 3) if P + R else None, "exact_tasks": sum(not r["fp"] and not r["fn"] for r in rows), "corroboration_agreement": f"{corr_agree}/{corr_n}", "tasks": rows}
tag = "" if (a.prompt_version, a.set) == ("v2", "dev") else f"_{a.prompt_version}_{a.set}"
out = ROOT / "experiments/envelopes" / f"accuracy_{a.compiler_model.replace(':', '_').replace('/', '_')}{tag}.json"
out.write_text(json.dumps(res, indent=1) + "\n")
print(json.dumps({k: v for k, v in res.items() if k != "tasks"}))
for r in rows:
    if r["fp"] or r["fn"] or r["compile_error"]: print(r)
