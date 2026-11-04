"""OTP-aware ground-truth replay (Week 3 harness; D-015 follow-up).

AgentDyn's shopping/github/dailylife reference solutions hard-code the placeholder "ONE-TIME-PASSWD"
where a live agent would read a freshly generated 6-digit OTP from the inbox (the tools generate a random
OTP, email it, and park the action until verify_*(otp) is called). Static replay therefore fails even
on the original benchmark. This replay executes ground-truth calls one by one on the live environment and,
for any `otp` argument, substitutes the most recent OTP found in the environment's emails at that moment,
which is exactly what an agent would do. Nothing else is changed.

  PYTHONPATH=<tree>/src .venv/bin/python experiments/harness/otp_replay.py <label> [suite ...]
Writes experiments/harness/otp_replay_<label>.json: per task, utility under OTP-aware replay, with any
error, and the OTP substitutions made.
"""
import json, pathlib, re, sys
import agentdojo
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

OTP_RE = re.compile(r"OTP[^0-9]{0,40}?(\d{6})")
HERE = pathlib.Path(__file__).resolve().parent


def _walk(o):
    if isinstance(o, dict):
        yield o
        for v in o.values(): yield from _walk(v)
    elif isinstance(o, list):
        for v in o: yield from _walk(v)


def latest_otp(env):
    """Most recent 6-digit OTP in any email-like record (dict with 'body'), by timestamp."""
    best = None
    for d in _walk(env.model_dump(mode="python")):  # python mode: pending-action callables in verification stacks aren't JSON-serialisable
        body = d.get("body")
        if isinstance(body, str):
            m = OTP_RE.search(body)
            if m:
                ts = str(d.get("timestamp", ""))
                if best is None or ts >= best[0]: best = (ts, m.group(1))
    return best[1] if best else None


def replay(suite, task):
    env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
    pre = env.model_copy(deep=True)
    rt = FunctionsRuntime(suite.tools)
    subs, errors = [], []
    for c in task.ground_truth(pre.model_copy(deep=True)):
        args = dict(c.args or {})
        for k, v in list(args.items()):
            if k == "otp" or v == "ONE-TIME-PASSWD":
                otp = latest_otp(env)
                if otp is not None:
                    subs.append({"call": c.function, "arg": k, "placeholder": v, "otp": otp}); args[k] = otp
        _, err = rt.run_function(env, c.function, args)
        if err: errors.append(f"{c.function}: {err[:120]}")
    out = getattr(task, "GROUND_TRUTH_OUTPUT", "") or ""
    try:
        util = task.utility(out, pre, env)
    except Exception as e:
        util = f"error: {type(e).__name__}: {str(e)[:120]}"
    return util, subs, errors


if __name__ == "__main__":
    label, wanted = sys.argv[1], set(sys.argv[2:])
    res = {"agentdojo_path": str(pathlib.Path(agentdojo.__file__).parent), "suites": {}}
    for name, suite in get_suites("v1.2.2").items():
        if wanted and name not in wanted: continue
        rows = {}
        for tid, task in suite.user_tasks.items():
            try:
                util, subs, errs = replay(suite, task)
            except Exception as e:
                util, subs, errs = f"error: {type(e).__name__}: {str(e)[:120]}", [], []
            rows[tid] = {"utility": util, "otp_substitutions": subs, "call_errors": errs}
        ok = sum(r["utility"] is True for r in rows.values())
        res["suites"][name] = {"pass": ok, "total": len(rows), "tasks": rows}
        print(f"{label:22s} {name:10s} OTP-aware benign replay utility {ok}/{len(rows)}")
    (HERE / f"otp_replay_{label}.json").write_text(json.dumps(res, indent=1, default=str) + "\n")
