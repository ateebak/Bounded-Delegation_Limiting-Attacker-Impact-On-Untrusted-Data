"""Paired task-level contrasts between conditions (protocol v2 §8): task = unit; per-task clean utility is the mean
over repeats; differences are averaged over the tasks BOTH conditions ran (e.g. ROPE has no workspace floor) with a
task-cluster bootstrap 95% CI, for strict utility and for utility incl. correctly staged actions (D-032). Also prints the per-task utility table and per-task attack outcomes (successes,
worst excess paid, worst attacker actions). Reads INVALID.json via analyze_repeats.

  .venv/bin/python experiments/harness/paired_contrasts.py name=RUN_ID [name=RUN_ID ...] [--pairs a:b,a:b]
"""
import collections, json, pathlib, random, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import analyze_repeats as A


def per_task(run_id, bad, staged=False):
    cfg = A.config(run_id)
    ref = cfg.get("ceiling") if cfg.get("defense") == "bounded" and cfg.get("ceiling") else 500
    u, atk = collections.defaultdict(list), collections.defaultdict(list)
    for e in A.load(run_id, bad):
        if e.get("error"): continue
        if e.get("attack") is None: u[e["task_key"]].append(e["utility"] is True or (staged and e.get("staged_correct") is True))
        else: atk[e["task_key"]].append((e["attack_success"] is True,) + A.impact(e, ref, cfg.get("tree", "fc")))
    return {k: sum(v) / len(v) for k, v in u.items()}, atk


def boot(x, y, keys, B=5000, seed=0):
    d = [x[k] - y[k] for k in keys]
    if not d: return None
    rng = random.Random(seed)
    bs = sorted(sum(d[rng.randrange(len(d))] for _ in d) / len(d) for _ in range(B))
    return round(sum(d) / len(d), 3), (round(bs[int(.025 * B)], 3), round(bs[int(.975 * B)], 3)), len(d)


if __name__ == "__main__":
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    pairs = next((x.split("=", 1)[1] for x in sys.argv[1:] if x.startswith("--pairs=")), "")
    runs = dict(a.split("=", 1) for a in args)
    bad = A.invalid()
    U, ATK, US = {}, {}, {}
    for n, r in runs.items():
        U[n], ATK[n] = per_task(r, bad)
        US[n], _ = per_task(r, bad, staged=True)
    for p in [p for p in pairs.split(",") if p]:
        a, b = p.split(":")
        keys = sorted(set(U[a]) & set(U[b]))
        m, ci, n = boot(U[a], U[b], keys); ms, cis, _ = boot(US[a], US[b], keys)
        print(json.dumps({"contrast": f"{a} - {b}", "n_tasks": n, "strict": {"mean_diff": m, "ci95": ci},
                          "incl_staged": {"mean_diff": ms, "ci95": cis}}))
    names = list(runs)
    print("\nper-task clean utility (mean over repeats)\n" + f"{'task':34s}" + "".join(f"{n[:14]:>16s}" for n in names))
    for k in sorted(set().union(*U.values())):
        print(f"{k:34s}" + "".join(f"{U[n].get(k, float('nan')):16.2f}" for n in names))
    print("\nattack outcomes per task: successes/n, worst excess paid, worst attacker actions")
    for k in sorted(set().union(*ATK.values())):
        cells = []
        for n in names:
            v = ATK[n].get(k, [])
            cells.append(f"{sum(s for s, *_ in v)}/{len(v)} x{max((x for _, x, _, _ in v), default=0):.0f} a{max((a for _, _, a, _ in v), default=0)}")
        print(f"{k:34s}" + "".join(f"{c:>16s}" for c in cells))
