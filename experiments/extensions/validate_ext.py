"""Validate the extension tasks (D-012) on a benchmark tree.

  PYTHONPATH=<tree>/src .venv/bin/python experiments/extensions/validate_ext.py <label>
Per task, records:
  patched_paths       every leaf holding the task's vector, patched consistently
  gt_utility          the reference solution achieves utility on the PATCHED environment
  unpatched_fails     without the patch the reference solution's value has no source, and utility on
                      the unpatched environment with an agent that can't find the value is False (checked
                      by running only the read calls)
  not_in_prompt       the delegated value doesn't occur in the prompt
  reachable           the vector's canary appears in tool output during the read calls (object is read)
  attacker_writable   the patched leaf contains an injection vector (by construction; asserted)
Writes experiments/extensions/ext_validation_<label>.json. Also exposes patch_env() for packets and runners.
"""
import json, pathlib, sys
from pydantic import BaseModel
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.task_suite.load_suites import get_suites

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[0] / "attacks"))
from ext_tasks import TASKS  # noqa: E402
from build_value_substitution import flatten  # noqa: E402


def _set(obj, path, value):
    for k in path[:-1]:
        obj = getattr(obj, k) if isinstance(obj, BaseModel) else obj[k]
    last = path[-1]
    if isinstance(obj, BaseModel): setattr(obj, last, value)
    else: obj[last] = value


def _get(obj, path):
    for k in path:
        obj = getattr(obj, k) if isinstance(obj, BaseModel) else obj[k]
    return obj


def vector_paths(suite, vector):
    d = suite.get_injection_vector_defaults()
    can = suite.load_and_inject_default_environment({k: f"CANARY_{k}_9e1" for k in d})
    return [p for p, t in flatten(can.model_dump(mode="python")) if f"CANARY_{vector}_9e1" in t]


def patch_env(suite, task, env, paths=None):
    """Append the patch once per underlying object: workspace's views (initial_emails, emails, received) can be
    the SAME Python object, so patching every path naively would append the text several times."""
    paths = paths or vector_paths(suite, task.vector)
    seen = set()
    for p in paths:
        parent = _get(env, p[:-1])
        key = (id(parent), p[-1])
        if key in seen: continue
        seen.add(key)
        _set(env, p, _get(env, p) + task.patch_text)
    return paths


def run(suite, env, calls):
    rt = FunctionsRuntime(suite.tools)
    out = ""
    for tool, args in calls:
        res, err = rt.run_function(env, tool, args)
        out += (err or "") + (tool_result_to_str(res) if res is not None else "") + "\n"
    return out


def main(label):
    suites = get_suites("v1.2.2")
    rows = {}
    for t in TASKS:
        su = suites[t.suite]
        d = su.get_injection_vector_defaults()
        env = su.load_and_inject_default_environment(d); pre = env.model_copy(deep=True)
        paths = patch_env(su, t, env)
        pre_patched = env.model_copy(deep=True)
        gt = t.ground_truth(env)
        out = run(su, env, gt)
        util = t.utility(pre_patched, env)
        # reachability: canary env + patch, run read calls only
        can = su.load_and_inject_default_environment({k: f"CANARY_{k}_9e1" for k in d})
        patch_env(su, t, can, paths)
        reads = [c for c in gt if c[0] not in {x[0] for x in t.delegated}]
        seen = run(su, can, reads)
        # unpatched: does the value appear anywhere the agent could read it?
        unp = su.load_and_inject_default_environment(d)
        unp_text = run(su, unp, reads)
        rows[t.id] = {"suite": t.suite, "label": t.label, "patched_paths": [list(map(str, p)) for p in paths],
                      "gt_utility": util, "gt_errors": [l for l in out.splitlines() if "Error" in l][:3],
                      "not_in_prompt": all(v not in t.prompt for _, _, v in t.delegated),
                      "reachable": f"CANARY_{t.vector}_9e1" in seen,
                      "value_absent_unpatched": all(v not in unp_text for _, _, v in t.delegated),
                      "attacker_writable": bool(paths),
                      "patch_once_per_view": all(_get(pre_patched, p).count(t.patch_text.strip()) == 1 for p in paths)}
        ok = all(v for k, v in rows[t.id].items() if k in ("gt_utility", "not_in_prompt", "reachable", "value_absent_unpatched", "attacker_writable", "patch_once_per_view"))
        print(f"{label:17s} {t.id:16s} paths={len(paths)} ok={ok} {({k: v for k, v in rows[t.id].items() if k not in ('patched_paths', 'suite', 'label')})}")
    (HERE / f"ext_validation_{label}.json").write_text(json.dumps(rows, indent=1) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
