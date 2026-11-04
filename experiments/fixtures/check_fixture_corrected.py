"""Validate a benchmark tree (original or fixture_corrected) by replaying reference solutions (D-015).

Run once per tree; the agentdojo package is taken from PYTHONPATH:
  PYTHONPATH=external/AgentDyn/src    .venv/bin/python experiments/fixtures/check_fixture_corrected.py original
  PYTHONPATH=external/AgentDyn-fc/src .venv/bin/python experiments/fixtures/check_fixture_corrected.py fixture_corrected
Checks, for every suite in benchmark v1.2.2:
  1. the benchmark's own suite.check() (canary environment; user utility and injection security);
  2. benign replay: each user task's ground truth on the DEFAULT environment (where corrected bill/web
     texts appear) must achieve utility;
  3. each injection task's ground truth on the default environment must achieve its security goal
     (i.e. the attack still works when executed).
Writes experiments/fixtures/check_<label>.json. Compare the two files: fixture_corrected must not
introduce any new failure.
"""
import json, pathlib, sys
import agentdojo
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.task_suite.load_suites import get_suites

label = sys.argv[1]
OUT = pathlib.Path(__file__).resolve().parent / f"check_{label}.json"
res = {"agentdojo_path": str(pathlib.Path(agentdojo.__file__).parent), "suites": {}}
for name, suite in get_suites("v1.2.2").items():
    try:
        ok_all, (ut_res, inj_res) = suite.check(check_injectable=False)
    except Exception as e:  # a pre-existing benchmark bug aborts suite.check(); record it and continue
        ok_all, ut_res, inj_res = f"error: {type(e).__name__}: {str(e)[:120]}", {}, {}
    defaults = suite.get_injection_vector_defaults()
    benign_fail, inj_fail = [], []
    for ut in suite.user_tasks.values():
        env = suite.load_and_inject_default_environment(defaults)
        try:
            utility, _ = suite.run_task_with_pipeline(GroundTruthPipeline(ut), ut, injection_task=None, injections={}, environment=env)
        except Exception as e:
            utility = False; benign_fail.append(f"{ut.ID} (error: {type(e).__name__}: {str(e)[:100]})"); continue
        if not utility: benign_fail.append(ut.ID)
    for it in suite.injection_tasks.values():
        env = suite.load_and_inject_default_environment(defaults)
        pre = env.model_copy(deep=True)
        from agentdojo.functions_runtime import FunctionsRuntime
        rt = FunctionsRuntime(suite.tools)
        for c in it.ground_truth(pre.model_copy(deep=True)):
            rt.run_function(env, c.function, dict(c.args or {}))
        try:
            sec = it.security("", pre, env)
        except Exception as e:  # record, don't hide
            sec = f"error: {type(e).__name__}"
        if sec is not True: inj_fail.append([it.ID, str(sec)])
    res["suites"][name] = {"suite_check_ok": ok_all,
                           "suite_check_user_failures": sorted(k for k, v in ut_res.items() if not v[0]),
                           "suite_check_injection_failures": sorted(k for k, v in inj_res.items() if not v),
                           "benign_default_env_user_failures": sorted(benign_fail),
                           "injection_ground_truth_failures": sorted(inj_fail)}
    r = res["suites"][name]
    print(f"{label:17s} {name:10s} suite.check={ok_all!s:5s} user_fail={len(r['suite_check_user_failures'])} "
          f"inj_fail={len(r['suite_check_injection_failures'])} benign_fail={len(benign_fail)} inj_gt_fail={len(inj_fail)}")
OUT.write_text(json.dumps(res, indent=1) + "\n")
print("agentdojo from", res["agentdojo_path"])
