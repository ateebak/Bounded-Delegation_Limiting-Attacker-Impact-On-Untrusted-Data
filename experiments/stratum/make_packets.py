"""Build annotation packets for the delegated-authority pilot (handbook v0.3, D-007).

For each task: replay the ground-truth tool calls on the suite's default environment (benign
injection-vector defaults, i.e. what a legitimate run sees) and record the calls and read results.
Outputs:
  annotations/blind/<suite>__<task>.md      packet for annotator B: prompt, what the agent reads,
                                            the fields to label, and a JSON answer skeleton.
                                            Contains NO origin classes, NO injection tasks, NO A labels.
  annotations/context/<suite>__<task>.json  the same material in machine form (used by A and by the
                                            fixture audit).
Fields to label = ground-truth state-changing arguments whose value is not literally in the prompt
(from delegated_candidates_args.csv), destination/magnitude/identifier classes only. The script's
attacker-reachability classes are deliberately not copied into packets.

Usage: .venv/bin/python experiments/stratum/make_packets.py banking:user_task_0 slack:user_task_2 ...
"""
import csv, json, pathlib, sys
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.task_suite.load_suites import get_suites
from find_delegated_candidates import STATE_CHANGING, VERSION

HERE = pathlib.Path(__file__).resolve().parent
ANN = HERE / "annotations"
VERSION_HB = "v0.4"
AGENT_DEFAULT_ARGS = {"date", "save_dir", "local_dir_path"}  # chosen by the agent, not delegated (handbook v0.4, D-017)
MAX_CHARS = 30000  # large enough that no pilot packet hides the delegated source


def fields_for(suite, task):
    out = []
    with open(HERE / "delegated_candidates_args.csv") as f:
        for r in csv.DictReader(f):
            if (r["suite"], r["task"]) == (suite, task) and r["delegated_candidate"] == "True" \
                    and r["param_class"] in ("destination", "magnitude", "identifier_or_other"):
                out.append({"call": r["tool"], "arg": r["arg"], "legitimate_value": json.loads(r["value"]) if r["value"].startswith(("[", "{", '"')) or r["value"].replace(".", "", 1).isdigit() else r["value"]})
    seen, uniq = set(), []
    for x in out:
        k = (x["call"], x["arg"], json.dumps(x["legitimate_value"], default=str))
        if k not in seen: seen.add(k); uniq.append(x)
    return [x for x in uniq if x["arg"] not in AGENT_DEFAULT_ARGS], [x for x in uniq if x["arg"] in AGENT_DEFAULT_ARGS]


def build(spec, suites):
    """spec = '<suite>:<user_task_N>' (native) or 'ext:<ext_id>' (extension task, D-012; env patch applied)."""
    ext = None
    if spec.startswith("ext:"):
        sys.path.insert(0, str(HERE.parent / "extensions"))
        from ext_tasks import TASKS
        from validate_ext import patch_env
        from agentdojo.functions_runtime import FunctionCall
        ext = next(t for t in TASKS if t.id == spec[4:])
        suite_name, task_id = ext.suite, ext.id
        suite = suites[suite_name]
        env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
        patch_env(suite, ext, env)
        calls = [FunctionCall(function=f, args=a) for f, a in ext.ground_truth(env)]

        class _T: PROMPT = ext.prompt
        task = _T()
    else:
        suite_name, task_id = spec.split(":")
        suite = suites[suite_name]
        task = suite.user_tasks[task_id]
        env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
        calls = task.ground_truth(env.model_copy(deep=True))
    runtime = FunctionsRuntime(suite.tools)
    steps = []
    for c in calls:
        res, err = runtime.run_function(env, c.function, dict(c.args or {}))
        text = err or tool_result_to_str(res)
        steps.append({"tool": c.function, "args": dict(c.args or {}), "state_changing": c.function in STATE_CHANGING,
                      "result": text if len(text) <= MAX_CHARS else text[:MAX_CHARS] + f"\n…[truncated, {len(text)} chars]"})
    key = f"{suite_name}__{task_id}" if not ext else f"{suite_name}__{task_id.replace('ext_' + suite_name + '_', 'user_task_ext')}"
    ctx = {"task_key": key, "suite": suite_name, "task": task_id, "benchmark_version": VERSION,
           "prompt": task.PROMPT, "tools_available": sorted(t.name for t in suite.tools),
           "ground_truth_trajectory": steps}
    if ext:
        ctx["fields"] = [{"call": c, "arg": a, "legitimate_value": v} for c, a, v in ext.delegated]
        ctx["optional_agent_default_fields"] = []
        ctx["label"] = "extension"
    else:
        ctx["fields"], ctx["optional_agent_default_fields"] = fields_for(suite_name, task_id)
    (ANN / "context").mkdir(parents=True, exist_ok=True)
    (ANN / "context" / f"{key}.json").write_text(json.dumps(ctx, indent=1, default=str) + "\n")

    md = [f"# Annotation packet: `{key}` (original variant)", "",
          f"Annotate with `docs/annotation-handbook.md` ({VERSION_HB}). **Blind rules:** don't open annotator A's files, "
          "`research/delegated-stratum-survey.md`, the candidate CSV/JSON, or the benchmark's injection tasks until your labels are committed.", "",
          "## User prompt (trusted)", "", "> " + task.PROMPT.replace("\n", "\n> "), "",
          "## What a legitimate run does and reads", "",
          "Replay of the benchmark's reference solution on the default environment. Read-call outputs are shown as the agent would receive them.", ""]
    for i, st in enumerate(steps, 1):
        kind = "**state-changing**" if st["state_changing"] else "read"
        md += [f"### Step {i}: `{st['tool']}` ({kind})", "", "Arguments: `" + json.dumps(st["args"], default=str) + "`", ""]
        if not st["state_changing"]:
            md += ["```", st["result"], "```", ""]
    if any("One Time Password is incorrect" in st["result"] for st in steps):
        md += ["> **Replay caveat:** one-time-password (OTP) steps fail in this static replay because the OTP only exists in a live run. "
               "Ignore those failures; they're not part of the task's authority question.", ""]
    md += ["## Fields to annotate", ""]
    if ctx["fields"]:
        md += [f"{j}. `{f['call']}.{f['arg']}` = `{json.dumps(f['legitimate_value'], default=str)}`" for j, f in enumerate(ctx["fields"], 1)]
    else:
        md += ["_None flagged by the literal-match screen._ Decide whether any sensitive argument is nonetheless derived from content "
               "(e.g. a computed amount). Add fields to the skeleton if so, or set `stratum_decision` to `exclude`."]
    if ctx["optional_agent_default_fields"]:
        md += ["", "_Optional (agent-default, normally not annotated):_ " + ", ".join(f"`{f['call']}.{f['arg']}`" for f in ctx["optional_agent_default_fields"])]
    skeleton = {"task_key": key, "variant": "original", "annotator": "B", "handbook_version": VERSION_HB, "date": "YYYY-MM-DD",
                "stratum_decision": "include | exclude | ambiguous", "task_notes": "",
                "fields": [{"call": f["call"], "arg": f["arg"], "delegation_explicitness": "explicit | implicit | none",
                            "source_named": "", "attacker_can_write_value": "yes | no | unclear", "attacker_write_reason": "",
                            "trusted_corroboration_available": "yes | no | unclear", "corroboration_location": "",
                            "param_role": "destination | magnitude | object | free_text | ui_element",
                            "harm_if_attacker_controlled": "critical | high | moderate | low", "reversible": "yes | no | partial",
                            "legitimate_value_constraints": {}, "fixture_validity": "valid | n/a | invalid:<code>[+<code>]",
                            "clarification_nosuspicion": "yes | no", "clarification_cautious": "yes | no",
                            "partial_success": "", "confidence": "1 | 2 | 3", "notes": ""}
                           for f in ctx["fields"]]}
    md += ["", "## Your answer",
           f"Save as `experiments/stratum/annotations/{OUTDIR_B}/{key}.json` (it's validated against `annotations/schema_v04.json`). Replace every `a | b` choice with one value.", "",
           "```json", json.dumps(skeleton, indent=1), "```", ""]
    (ANN / BLIND_DIR).mkdir(parents=True, exist_ok=True)
    (ANN / BLIND_DIR / f"{key}.md").write_text("\n".join(md))
    return key, len(steps), len(ctx["fields"])


ROUND = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--round=")), "")
BLIND_DIR = f"blind_{ROUND}" if ROUND else "blind"
OUTDIR_B = f"B_{ROUND}" if ROUND else "B"

if __name__ == "__main__":
    suites = get_suites(VERSION)
    for spec in [a for a in sys.argv[1:] if not a.startswith("--")]:
        print(*build(spec, suites))
