"""Offline cross-check: do ROPE's fail-closed clean-task losses fall inside our delegated stratum?

Reads ROPE's shipped run logs (external/ROPE/runs/<model>/<suite>/<task>/none/none.json;
github.com/xhOwenMa/ROPE, MIT) and our heuristic survey
(experiments/stratum/delegated_candidates_summary.json). No model calls.

A clean run is `denied_fail` if utility is False and at least one tool call was rejected
by ROPE's guard ("... is not allowed"). This is the utility ROPE gives up by failing
closed. It is exactly what bounded delegation aims to recover.

These are the ROPE authors' runs, not ours. The numbers describe their logs at the
pinned commit and are not a reproduction by us.
"""
import collections, json, pathlib, re, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNS = ROOT / "external/ROPE/runs"
SURVEY = json.loads((ROOT / "experiments/stratum/delegated_candidates_summary.json").read_text())
MODELS = ["gpt-4o-mini", "gpt-4o", "gemini-2.5-flash", "qwen3-235b"]
DENY = "is not allowed"
HIGH_HARM = re.compile(r"send_money|user_email|collaborator_email|send_email.recipients|send_direct_message.recipient|"
                       r"update_user_info|download_file_through_url.url|input_to_webpage.url|send_channel_message.channel|add_user_to_channel")


def stratum(suite, task):
    c = SURVEY["suites"].get(suite, {}).get("candidates", {}).get(task)
    if not c: return "outside"
    return "high_harm" if any(HIGH_HARM.search(a) for a in c["args"]) else "low_harm"


def main():
    per_task = collections.defaultdict(lambda: collections.Counter())
    for model in MODELS:
        for f in sorted((RUNS / model).glob("*/user_task_*/none/none.json")):
            d = json.loads(f.read_text())
            denied = any(m.get("role") == "tool" and DENY in str(m.get("error") or "") for m in d["messages"])
            outcome = "pass" if d["utility"] else ("denied_fail" if denied else "other_fail")
            per_task[(d["suite_name"], d["user_task_id"])][outcome] += 1
    table = collections.defaultdict(collections.Counter)
    rows = []
    for (suite, task), c in sorted(per_task.items()):
        s = stratum(suite, task)
        table[s].update(c)
        table[s]["tasks"] += 1
        if c["denied_fail"]: table[s]["tasks_with_denied_fail"] += 1
        rows.append(dict(suite=suite, task=task, stratum=s, **{k: c[k] for k in ("pass", "denied_fail", "other_fail")}))
    commit = subprocess.run(["git", "-C", str(ROOT / "external/ROPE"), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    out = {"rope_commit": commit, "models": MODELS, "unit": "clean run = (model, suite, user task)",
           "by_stratum": {k: dict(v) for k, v in table.items()}, "per_task": rows}
    (ROOT / "experiments/stratum/rope_clean_denials.json").write_text(json.dumps(out, indent=1) + "\n")
    print(f"ROPE commit {commit[:8]}; models: {', '.join(MODELS)}")
    print(f"{'stratum':10s} {'tasks':>5s} {'runs':>5s} {'pass':>5s} {'denied_fail':>11s} {'other_fail':>10s} {'tasks w/ denied_fail':>20s}")
    for s in ("high_harm", "low_harm", "outside"):
        v = table[s]; runs = v["pass"] + v["denied_fail"] + v["other_fail"]
        print(f"{s:10s} {v['tasks']:5d} {runs:5d} {v['pass']:5d} {v['denied_fail']:11d} {v['other_fail']:10d} {v['tasks_with_denied_fail']:20d}")


if __name__ == "__main__":
    main()
