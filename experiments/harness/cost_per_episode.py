"""Per-episode token and cost summary from experiments/costs/ledger.jsonl.

  .venv/bin/python experiments/harness/cost_per_episode.py <run_id> [<run_id> ...]
Ledger rows from the runner carry run_id = "<run_id>/<episode>". Reports, per run: episodes, LLM calls per episode,
input/output tokens per episode (mean and max), and estimated $ per episode at list price (NIM = $0; the
equivalent cost at a reference price is also shown so free-tier episodes can be extrapolated to paid models).
"""
import collections, json, pathlib, statistics, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER = ROOT / "experiments/costs/ledger.jsonl"
REF = {"claude-sonnet-5-5": (2.0, 10.0), "gpt-6.1-sol": (2.0, 10.0), "claude-opus-5-5": (4.0, 20.0), "gpt-5.5": (5.0, 30.0)}


def main(run_ids):
    rows = [json.loads(l) for l in LEDGER.read_text().splitlines() if l.strip()]
    for rid in run_ids:
        eps = collections.defaultdict(lambda: {"calls": 0, "in": 0, "out": 0, "usd": 0.0})
        for r in rows:
            if str(r["run_id"]).startswith(rid + "/"):
                e = eps[r["run_id"]]; e["calls"] += 1; e["in"] += r["input_tokens"]; e["out"] += r["output_tokens"]
                e["usd"] += r["est_usd"] or 0.0
                model = r["model"]
        if not eps:
            print(f"{rid}: no ledger rows"); continue
        ins, outs = [e["in"] for e in eps.values()], [e["out"] for e in eps.values()]
        print(f"{rid} ({model}): episodes={len(eps)} calls/ep={statistics.mean(e['calls'] for e in eps.values()):.1f} "
              f"in/ep mean={statistics.mean(ins):.0f} max={max(ins)} out/ep mean={statistics.mean(outs):.0f} max={max(outs)} "
              f"$/ep={statistics.mean(e['usd'] for e in eps.values()):.4f}")
        for ref, (pi, po) in REF.items():
            print(f"    at {ref} list price: ${(statistics.mean(ins) * pi + statistics.mean(outs) * po) / 1e6:.4f}/episode "
                  f"(no caching; upper bound)")


if __name__ == "__main__":
    main(sys.argv[1:])
