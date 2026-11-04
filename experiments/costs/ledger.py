"""Append-only token and cost ledger for every paid (or free-tier) model call in this study.

Each call appends one JSON line to experiments/costs/ledger.jsonl:
  {ts, run_id, provider, interface, model, input_tokens, cached_input_tokens, output_tokens,
   reasoning_tokens, est_usd, free_allotment, price_source}
est_usd is list-price-equivalent from pricing.json. Rows with free_allotment=true are models
the user reported as covered by free usage; real spend is the sum over rows where it is false.
CLI rows (Claude Code / Codex) carry the CLI's own reported cost when available.

Budget (D-013, amended): guard() is called before every direct OpenAI/Anthropic API call only.
CLI (Claude Code/Codex) rows are recorded but neither guarded nor counted toward the cap. It raises BudgetStop once real spend
reaches stop_and_ask_fraction x cap (default 80% of $250) so a human decides. The cap itself is
never exceeded by design; override only with the user's approval (env LEDGER_BUDGET_ACK=<cap> after
they approve continuing past the stop point).

Summary: .venv/bin/python experiments/costs/ledger.py
"""
import collections, datetime, json, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "ledger.jsonl"
PRICING = json.loads((HERE / "pricing.json").read_text())
FREE = set(PRICING["user_reported_free_allotment"]["openai"])
BUDGET = json.loads((HERE / "budget.json").read_text())


class BudgetStop(SystemExit):
    pass


def real_spend():
    if not LEDGER.exists(): return 0.0
    rows = [json.loads(l) for l in LEDGER.read_text().splitlines() if l.strip()]
    # Only direct OpenAI/Anthropic API spend counts toward the cap (user decision, D-013 amended):
    # Claude Code / Codex CLI runs are subscription-billed and tracked but not capped.
    return sum((r["est_usd"] or 0) for r in rows if r["interface"] == "api" and not r["free_allotment"])


def guard(provider, model):
    """Call before a paid request. Free/local providers and free-allotment models pass through."""
    import os
    if provider not in ("openai", "anthropic") or (provider == "openai" and model in FREE): return
    spent, cap = real_spend(), BUDGET["cap_usd"]
    ack = float(os.environ.get("LEDGER_BUDGET_ACK", 0) or 0)
    if spent >= cap:
        raise BudgetStop(f"Budget cap reached: ${spent:.2f} of ${cap:.2f}. Stop; ask the user.")
    if spent >= BUDGET["stop_and_ask_fraction"] * cap and ack < cap:
        raise BudgetStop(f"Spend ${spent:.2f} is at {spent/cap:.0%} of the ${cap:.0f} cap. Stop and ask the user; "
                         f"continue only with their approval (LEDGER_BUDGET_ACK={cap:.0f}).")


def _price(provider, model):
    table = PRICING.get(provider, {})
    if model in table: return table[model]
    for k, v in table.items():  # dated snapshot ids, e.g. claude-haiku-4-5-20251001
        if not k.startswith("_") and model.startswith(k): return v
    return None


def record(run_id, provider, interface, model, input_tokens=0, cached_input_tokens=0, output_tokens=0,
           reasoning_tokens=0, reported_usd=None):
    p = _price(provider, model)
    if reported_usd is not None:
        est = float(reported_usd)
    elif p is None:
        est = 0.0 if provider in ("nim", "ollama") else None
    else:
        uncached = max(input_tokens - cached_input_tokens, 0)
        est = (uncached * p[0] + cached_input_tokens * p[1] + output_tokens * p[2]) / 1e6
    row = dict(ts=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), run_id=run_id,
               provider=provider, interface=interface, model=model, input_tokens=input_tokens,
               cached_input_tokens=cached_input_tokens, output_tokens=output_tokens,
               reasoning_tokens=reasoning_tokens, est_usd=None if est is None else round(est, 6),
               free_allotment=(provider == "openai" and model in FREE),
               price_source="cli_reported" if reported_usd is not None else ("pricing.json" if p else "none"))
    with open(LEDGER, "a") as f: f.write(json.dumps(row) + "\n")
    return row


def summary():
    rows = [json.loads(l) for l in LEDGER.read_text().splitlines()] if LEDGER.exists() else []
    agg = collections.defaultdict(lambda: collections.Counter())
    for r in rows:
        k = (r["provider"], r["interface"], "free" if r["free_allotment"] else "paid")
        a = agg[k]; a["calls"] += 1; a["in"] += r["input_tokens"]; a["out"] += r["output_tokens"]
        a["usd_milli"] += int(round((r["est_usd"] or 0) * 1000))
        if r["est_usd"] is None: a["unpriced"] += 1
    total_paid = sum(v["usd_milli"] for k, v in agg.items() if k[2] == "paid" and k[1] == "api") / 1000
    cli = sum(v["usd_milli"] for k, v in agg.items() if k[1] != "api") / 1000
    print(f"{'provider':10s} {'interface':10s} {'billing':7s} {'calls':>6s} {'in_tok':>9s} {'out_tok':>9s} {'est_usd':>9s}")
    for k, v in sorted(agg.items()):
        print(f"{k[0]:10s} {k[1]:10s} {k[2]:7s} {v['calls']:6d} {v['in']:9d} {v['out']:9d} {v['usd_milli']/1000:9.3f}"
              + (f"  ({v['unpriced']} unpriced)" if v["unpriced"] else ""))
    print(f"CLI (subscription, not capped) list-price equivalent: ${cli:.3f}")
    print(f"Capped API spend (non-free rows): ${total_paid:.3f} of ${BUDGET['cap_usd']:.0f} cap "
          f"({total_paid/BUDGET['cap_usd']:.1%}); stop-and-ask at {BUDGET['stop_and_ask_fraction']:.0%}")


if __name__ == "__main__":
    summary()
