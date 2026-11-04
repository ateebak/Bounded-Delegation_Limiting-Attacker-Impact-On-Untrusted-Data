"""Resolving replay: the OTP-aware replay (otp_replay.py) plus resolution of the other placeholders that reference
trajectories leave for a live agent: INVITATION_LINK (newest invitation URL in any inbox), last-order-id (newest order
of the logged-in shopping account), file_id placeholders / non-existent ids (newest string attachment id). Used by
oracle_diagnosis.py. Nothing about the task, environment or check is changed.
"""
import json, re, sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from otp_replay import latest_otp, _walk
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
S = get_suites("v1.2.2")

def emails(env):
    for d in _walk(env.model_dump(mode="python")):
        if isinstance(d.get("body"), str) and "sender" in d: yield d

def newest(env, pred):
    best = None
    for e in emails(env):
        v = pred(e)
        if v and (best is None or str(e.get("timestamp", "")) >= best[0]): best = (str(e.get("timestamp", "")), v)
    return best and best[1]

def resolve(env, fn, args, files):
    notes = []
    for k, v in list(args.items()):
        if k == "otp" or v in ("ONE-TIME-PASSWD", "one-time-password"):
            args[k] = latest_otp(env); notes.append(f"{k}=OTP")
        elif v == "INVITATION_LINK":
            args[k] = newest(env, lambda e: (re.findall(r"https://www\.github_receive_invitation\.com/\S+", e["body"]) or [None])[-1]); notes.append(f"{k}={args[k]}")
        elif v == "last-order-id":
            acc = env.shopping_platform.account_list
            cur = next(a for a in acc if getattr(a, "username", None) == env.shopping_platform.current_account_username) if env.shopping_platform.current_account_username else acc[0]
            args[k] = cur.order_history[-1].order_id; notes.append(f"{k}={args[k]}")
        elif k == "file_id" and (v not in env.web_database.file_list or v in ("ID", "file_id")):
            nf = newest(env, lambda e: [a for a in (e.get("attachments") or []) if isinstance(a, str)][-1:] or None)
            args[k] = nf and nf[0]; notes.append(f"{k}:{v}->{args[k]}")
        elif k == "attachments" and isinstance(v, list):
            new = []
            for a in v:
                if isinstance(a, dict) and a.get("file_id") in ("file_id", "ID"):
                    nf = newest(env, lambda e: [x for x in (e.get("attachments") or []) if isinstance(x, str)][-1:] or None)
                    a = {**a, "file_id": nf and nf[0]}; notes.append(f"attachment->{a['file_id']}")
                new.append(a)
            args[k] = new
    return notes

def run(key, extra=(), drop=()):
    s, t = key.split("__"); su = S[s]; task = su.user_tasks[t]
    env = su.load_and_inject_default_environment(su.get_injection_vector_defaults())
    pre = env.model_copy(deep=True); rt = FunctionsRuntime(su.tools); log = []
    calls = [(c.function, dict(c.args or {})) for c in task.ground_truth(pre.model_copy(deep=True))]
    calls = [c for i, c in enumerate(calls) if i not in drop] + list(extra)
    for fn, args in calls:
        notes = resolve(env, fn, args, None)
        res, err = rt.run_function(env, fn, args)
        log.append((fn, notes, (err or str(res))[:160]))
    out = getattr(task, "GROUND_TRUTH_OUTPUT", "") or ""
    try: u = task.utility(out, pre, env)
    except Exception as e: u = f"error {e}"
    return u, log, pre, env

