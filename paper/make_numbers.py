"""Generate the manuscript's numbers from committed analysis outputs and run records (roadmap: "headline numbers are
generated, never typed in by hand"). Writes paper/generated/:
  numbers.tex   \\N{key} lookups (an undefined key stops the LaTeX build), with the source run ID in a comment;
  tab_*.tex     tables;  fig_*.pdf  figures.
Keys:
  <tag>/<condition>/<field>   from experiments/probes/logs/<tag>_analysis.jsonl (analyze_repeats.py); fields: utility,
                              utility_incl_staged, attack_success, beyond_envelope, excess_paid_max, attacker_actions_max,
                              utility_pct, utility_incl_pct, beyond_hi (Wilson upper bound, %), episodes, harness_errors
  <tag>/<a - b>/strict|incl   "+29.3 [+13.3, +48.0]" pp from <tag>_contrasts.txt (paired_contrasts.py); .../strict-pt|incl-pt
  burden/<tag>/<condition>/clean|attack   confirmation prompts per valid episode (run records, INVALID.json applied)
  compiler/<set>/<field>      experiments/envelopes/accuracy_anthropic_claude-sonnet-5-5<suffix>.json
  .venv/bin/python paper/make_numbers.py"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOGS = ROOT / "experiments/probes/logs"
OUT = ROOT / "paper/generated"
sys.path.insert(0, str(ROOT / "experiments/harness"))
import analyze_repeats as A

# Analysis outputs the paper may cite (findings F-17..F-37, F-A3..F-A6, F-P1..F-P3).
TAGS = ["pilot_repeats", "pilot_repeats_v4", "eval-s1", "eval-s1-simsweep", "eval-s1b-progent-approver",
        "eval-s1c-hardcaps", "eval-s1d-plausible-fixseed", "eval-s2", "eval-s3-authored-v2", "eval-s4-nemotron",
        "eval-s7-sonnet", "eval-s7-gpt61", "eval-s8a-main", "eval-s8a-adaptive", "eval-s8b-replicate",
        "eval-s8b-nemotron", "eval-s8b-sonnet", "eval-s8b-gpt61", "eval-s8c-adaptive", "eval-s9-glm53",
        "eval-s10-minimax", "eval-d052-ablations"]
COMPILER = {"dev": "", "dev-v1": "_prompt-v1", "heldout": "_v2_heldout_authored"}
# Burden is computed for these (tag, condition) pairs.
BURDEN = [("eval-s8a-main", "new_perfect"), ("eval-s8a-main", "new_rubber"), ("eval-s8b-replicate", "nemotron_new"),
          ("eval-s8b-replicate", "sonnet_new"), ("eval-s8b-replicate", "gpt61_new"), ("eval-s10-minimax", "new"),
          ("eval-s1c-hardcaps", "hc_perfect"), ("eval-s1c-hardcaps", "hc_rubber"), ("eval-s1-simsweep", "perfect"), ("eval-s1b-progent-approver", "pg_perfect"),
          ("eval-s2", "modeB"), ("eval-s8a-adaptive", "adp_new"), ("eval-d052-ablations", "askfam_adp"),
          ("eval-d052-ablations", "askfam"), ("eval-d052-ablations", "relmax"),
          ("eval-s1c-hardcaps", "sc_perfect"), ("eval-s1c-hardcaps", "sc_rubber"), ("eval-s1c-hardcaps", "pg_perfect"),
          ("eval-s1c-hardcaps", "pg_rubber"), ("eval-s1d-plausible-fixseed", "bd_p05"), ("eval-s1d-plausible-fixseed", "bd_p09"),
          ("eval-s1d-plausible-fixseed", "pg_p05"), ("eval-s1d-plausible-fixseed", "pg_p09")] + \
         [("eval-s2", c) for c in ("c100", "c250", "c500", "c1000", "cnone")]

# Main results (five main models, D-051). "ours" = final design (LLM compiler v2, hard caps, ask-once, perfect user,
# ceiling 500, rel_max 0.10, credentials never delegable). Sources as cited in F-30, F-32, F-33, F-34.
MAIN = {
    "gemma-4-31b": {"none": ("eval-s1", "none"), "rope": ("eval-s1", "rope"), "progent": ("eval-s1", "progent"),
                    "drift": ("eval-s1", "drift"), "camel": ("eval-s1", "camel"), "ours": ("eval-s8a-main", "new_perfect")},
    "nemotron-3.5": {"none": ("eval-s4-nemotron", "none"), "rope": ("eval-s4-nemotron", "rope"),
                     "progent": ("eval-s4-nemotron", "progent"), "drift": ("eval-s4-nemotron", "drift"),
                     "camel": ("eval-s4-nemotron", "camel"), "ours": ("eval-s8b-replicate", "nemotron_new")},
    "minimax-m3.1": {"none": ("eval-s10-minimax", "none"), "rope": ("eval-s10-minimax", "rope"),
                     "progent": ("eval-s10-minimax", "progent"), "drift": ("eval-s10-minimax", "drift"),
                     "camel": ("eval-s10-minimax", "camel"), "ours": ("eval-s10-minimax", "new")},
    "Sonnet 5.5": {"none": ("eval-s7-sonnet", "none"), "rope": ("eval-s7-sonnet", "rope"),
                   "progent": ("eval-s7-sonnet", "progent"), "camel": ("eval-s7-sonnet", "camel"),
                   "ours": ("eval-s8b-replicate", "sonnet_new")},
    "gpt-6.1-sol": {"none": ("eval-s7-gpt61", "none"), "rope": ("eval-s7-gpt61", "rope"),
                    "progent": ("eval-s7-gpt61", "progent"), "camel": ("eval-s7-gpt61", "camel"),
                    "ours": ("eval-s8b-replicate", "gpt61_new")},
}
VS_ROPE = {"gemma-4-31b": ("eval-s8a-main", "new_perfect - rope"), "nemotron-3.5": ("eval-s8b-nemotron", "nemotron_new - nemotron_rope"),
           "minimax-m3.1": ("eval-s10-minimax", "new - rope"), "Sonnet 5.5": ("eval-s8b-sonnet", "sonnet_new - sonnet_rope"),
           "gpt-6.1-sol": ("eval-s8b-gpt61", "gpt61_new - gpt61_rope")}
COND = ["none", "rope", "progent", "drift", "camel", "ours"]


def analysis(tag):
    p = LOGS / f"{tag}_analysis.jsonl"
    if not p.exists(): return {}  # contrasts-only tags (eval-s8b-<model>)
    return {r["condition"]: r for r in (json.loads(l) for l in p.read_text().splitlines() if l.strip())}


def contrasts(tag):
    p = LOGS / f"{tag}_contrasts.txt"
    if not p.exists(): return {}
    return {r["contrast"]: r for r in (json.loads(l) for l in p.read_text().splitlines() if l.startswith("{"))}


def pp(x): return f"{x * 100:+.1f}".replace("-", "$-$") if x else "0.0"


def r2(x): from decimal import Decimal, ROUND_HALF_UP; return str(Decimal(str(x)).quantize(Decimal("0.01"), ROUND_HALF_UP))


def frac(s): k, n = map(int, s.split("/")); return k / n


def tex_escape(s): return str(s).replace("_", r"\_").replace("%", r"\%")


def main():
    OUT.mkdir(exist_ok=True)
    defs = {}  # key -> (value, comment)
    an = {t: analysis(t) for t in TAGS}
    for tag, rows in an.items():
        for c, r in rows.items():
            base = f"{tag}/{c}"
            for f in ("utility", "utility_incl_staged", "attack_success", "beyond_envelope", "episodes", "harness_errors",
                      "attacker_actions_max"):
                if f in r: defs[f"{base}/{f}"] = (r[f], r["run_id"])
            if "excess_paid_max" in r:
                defs[f"{base}/excess_paid_max"] = (f"{r['excess_paid_max']:,.2f}".rstrip("0").rstrip("."), r["run_id"])
            for f, k in (("utility", "utility_pct"), ("utility_incl_staged", "utility_incl_pct")):
                if r.get(f) and not r[f].endswith("/0"): defs[f"{base}/{k}"] = (f"{frac(r[f]) * 100:.0f}", r["run_id"])
            if r.get("beyond_ci"): defs[f"{base}/beyond_hi"] = (f"{r['beyond_ci'][1] * 100:.1f}", r["run_id"])
        for k, d in contrasts(tag).items():
            for m, lab in (("strict", "strict"), ("incl_staged", "incl")):
                x = d[m]
                defs[f"{tag}/{k}/{lab}"] = (f"{pp(x['mean_diff'])} [{pp(x['ci95'][0])}, {pp(x['ci95'][1])}]", f"n_tasks {d['n_tasks']}")
                defs[f"{tag}/{k}/{lab}-pt"] = (pp(x["mean_diff"]), f"n_tasks {d['n_tasks']}")
    bad = A.invalid()
    for tag, c in BURDEN:
        rid = an[tag][c]["run_id"]
        eps = [e for e in A.load(rid, bad) if not e.get("error")]
        for kind, sel in (("clean", lambda e: e.get("attack") is None), ("attack", lambda e: e.get("attack") is not None)):
            xs = [e.get("confirmation_prompts") or 0 for e in eps if sel(e)]
            if xs: defs[f"burden/{tag}/{c}/{kind}"] = (f"{sum(xs) / len(xs):.2f}", f"{rid} n={len(xs)}")
    for s, suf in COMPILER.items():
        d = json.loads((ROOT / f"experiments/envelopes/accuracy_anthropic_claude-sonnet-5-5{suf}.json").read_text())
        d.setdefault("f1", round(2 * d["precision"] * d["recall"] / (d["precision"] + d["recall"]), 3))
        for f in ("precision", "recall", "f1", "n_tasks", "exact_tasks"):
            defs[f"compiler/{s}/{f}"] = (d[f], f"accuracy{suf}.json")

    # Derived main-result summaries (five main models).
    dn, dr, natt, nbe = [], [], 0, 0
    for m, conds in MAIN.items():
        o, n = an[conds["ours"][0]][conds["ours"][1]], an[conds["none"][0]][conds["none"][1]]
        d = (frac(o["utility_incl_staged"]) - frac(n["utility_incl_staged"])) * 100; dn.append(d)
        defs[f"main/{m}/ours-none-raw"] = (f"{d:+.1f}".replace("-", "$-$"), "unpaired count difference, incl. staging")
        tag, key = VS_ROPE[m]; dr.append(contrasts(tag)[key]["incl_staged"]["mean_diff"] * 100)
        k, nn = map(int, o["beyond_envelope"].split("/")); natt += nn; nbe += k
    defs["main/n-models"] = (len(MAIN), "MAIN")
    defs["main/attack-episodes"] = (natt, "sum of ours attack episodes over MAIN")
    defs["main/ours-beyond-total"] = (nbe, "sum over MAIN")
    defs["main/vsrope-min"] = (f"{min(dr):+.1f}", "VS_ROPE incl"); defs["main/vsrope-max"] = (f"{max(dr):+.1f}", "VS_ROPE incl")
    defs["main/below-none-min"] = (f"{-max(dn):.1f}", "raw"); defs["main/below-none-max"] = (f"{-min(dn):.1f}", "raw")


    # Table: main results.
    rows = []
    for m, conds in MAIN.items():
        cells = []
        for c in COND:
            if c not in conds: cells.append("--"); continue
            r = an[conds[c][0]][conds[c][1]]
            ut, ui, be = r["utility"], r["utility_incl_staged"], r["beyond_envelope"]
            u = f"{ut} ({ui})" if ut != ui else ut
            cells.append(f"\\textbf{{{u}}} / \\textbf{{{be}}}" if c == "ours" else f"{u} / {be}")
        tag, key = VS_ROPE[m]; d = contrasts(tag)[key]["incl_staged"]
        rows.append(f"{m} & " + " & ".join(cells) + f" & {pp(d['mean_diff'])} [{pp(d['ci95'][0])}, {pp(d['ci95'][1])}] \\\\")
    (OUT / "tab_main.tex").write_text(
        "% GENERATED by paper/make_numbers.py; do not edit.\n\\begin{tabular}{lccccccc}\n\\toprule\n"
        "Model & Undefended & ROPE & Progent & DRIFT & CaMeL & Ours & Ours$-$ROPE (pp) \\\\\n\\midrule\n"
        + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

    # Table: simulated-user panel (gemma; ceiling 500; no relative caps). Soft caps at plausible-p are invalid (F-25).
    def cell(tag, c, extra=""):
        r = an[tag][c]; b = defs.get(f"burden/{tag}/{c}/clean", ("--",))[0]
        return f"{r['utility_incl_staged']} & {r['beyond_envelope']} & {b}"
    users = [("perfect", ("eval-s1c-hardcaps", "sc_perfect"), ("eval-s1c-hardcaps", "hc_perfect"), ("eval-s1c-hardcaps", "pg_perfect")),
             ("rubber-stamp", ("eval-s1c-hardcaps", "sc_rubber"), ("eval-s1c-hardcaps", "hc_rubber"), ("eval-s1c-hardcaps", "pg_rubber")),
             ("plausible 0.9", None, ("eval-s1d-plausible-fixseed", "bd_p09"), ("eval-s1d-plausible-fixseed", "pg_p09")),
             ("plausible 0.5", None, ("eval-s1d-plausible-fixseed", "bd_p05"), ("eval-s1d-plausible-fixseed", "pg_p05"))]
    rows = [f"{u} & " + " & ".join(cell(*x) if x else "\\multicolumn{3}{c}{invalid (seed bug)}" for x in xs) + " \\\\"
            for u, *xs in users]
    (OUT / "tab_users.tex").write_text(
        "% GENERATED by paper/make_numbers.py; do not edit.\n\\begin{tabular}{@{}l@{\\quad}ccc@{\\quad}ccc@{\\quad}ccc@{}}\n\\toprule\n"
        "& \\multicolumn{3}{c}{Ours, soft caps} & \\multicolumn{3}{c}{Ours, hard caps} & \\multicolumn{3}{c}{Progent + approver} \\\\\n"
        "User & Util. & Beyond & Pr. & Util. & Beyond & Pr. & Util. & Beyond & Pr. \\\\\n\\midrule\n" + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n")

    # Table: ceiling frontier (gemma; hard caps; no relative caps).
    rows = []
    for c, lab in (("c100", "100"), ("c250", "250"), ("c500", "500"), ("c1000", "1,000"), ("cnone", "none"), ("modeB", "stage all")):
        r = an["eval-s2"][c]; d = contrasts("eval-s2")[f"{c} - rope"]["incl_staged"]
        rows.append(f"{lab} & {r['utility_incl_staged']} & {r['beyond_envelope']} & {r['excess_paid_max']:,.0f} & "
                    f"{pp(d['mean_diff'])} [{pp(d['ci95'][0])}, {pp(d['ci95'][1])}] \\\\")
    (OUT / "tab_frontier.tex").write_text(
        "% GENERATED by paper/make_numbers.py; do not edit.\n\\begin{tabular}{@{}lcccc@{}}\n\\toprule\n"
        "Ceiling & Utility & Beyond & Max excess & vs.\\ ROPE (pp) \\\\\n\\midrule\n" + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n")

    # Table: annotation agreement (round v0.4; Cohen's kappa per pair; A = Claude, B = author, C = Codex).
    ag = json.loads((ROOT / "experiments/stratum/annotations/agreement_v04.json").read_text())
    fields = ["attacker_can_write_value", "delegation_explicitness", "trusted_corroboration_available", "param_role",
              "harm_if_attacker_controlled", "reversible", "clarification_cautious"]
    rows = [f"stratum decision (raw) & " + " & ".join(r2(ag[p]['stratum_decision_agreement']) for p in ("A-B", "A-C", "B-C")) + " \\\\"]
    for f in fields:
        rows.append(tex_escape(f) + " & " + " & ".join(r2(ag[p]['per_field'][f]['cohen_kappa']) for p in ("A-B", "A-C", "B-C")) + " \\\\")
    n = ag["A-B"]["per_field"][fields[0]]["n"]; defs["annot/fields"] = (n, "agreement_v04.json"); defs["annot/tasks"] = (len(ag["A-B"]["tasks_compared"]), "agreement_v04.json")
    (OUT / "tab_annot.tex").write_text(
        "% GENERATED by paper/make_numbers.py; do not edit.\n\\begin{tabular}{@{}lccc@{}}\n\\toprule\n"
        "Field & A--B & A--C & B--C \\\\\n\\midrule\n" + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

    # Figure: clean utility vs beyond-envelope rate, per model and defense.
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    mk = {"none": ("o", "Undefended"), "rope": ("s", "ROPE"), "progent": ("^", "Progent"), "drift": ("v", "DRIFT"),
          "camel": ("D", "CaMeL"), "ours": ("*", "Ours")}
    col = dict(zip(MAIN, ["#1b9e77", "#d95f02", "#7570b3", "#e7298a", "#66a61e"]))
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    for m, conds in MAIN.items():
        for c, (tag, name) in conds.items():
            r = an[tag][name]
            ax.scatter(frac(r["utility_incl_staged"]) * 100, frac(r["beyond_envelope"]) * 100, marker=mk[c][0],
                       color=col[m], s=60 if c == "ours" else 22, edgecolor="black" if c == "ours" else "none", linewidth=0.5, zorder=3)
    from matplotlib.lines import Line2D
    h1 = [Line2D([], [], marker=mk[c][0], ls="", color="gray", label=mk[c][1]) for c in COND]
    h2 = [Line2D([], [], marker="o", ls="", color=col[m], label=m) for m in MAIN]
    ax.legend(handles=h1 + h2, fontsize=5.5, ncol=2, loc="upper left", frameon=False)
    ax.set_xlabel("Clean utility incl. staging (%)", fontsize=7); ax.set_ylabel("Beyond-envelope attacks (%)", fontsize=7)
    ax.tick_params(labelsize=6); ax.set_xlim(0, 100); ax.set_ylim(-1.5, 35); ax.grid(alpha=0.3, lw=0.4)
    fig.tight_layout(); fig.savefig(OUT / "fig_main.pdf", metadata={"CreationDate": None, "ModDate": None}); plt.close(fig)
    lines = ["% GENERATED by paper/make_numbers.py; do not edit.",
             r"\makeatletter",
             r"\newcommand{\N}[1]{\ifcsname bdn@#1\endcsname\csname bdn@#1\endcsname\else\errmessage{Undefined number key: #1}\fi}",
             r"\newcommand{\bd@def}[2]{\expandafter\def\csname bdn@#1\endcsname{#2}}"]
    for k, (v, src) in sorted(defs.items()):
        lines.append(f"\\bd@def{{{k}}}{{{tex_escape(v) if not str(v).startswith(('+', '$', '0', '-')) else v}}} % {src}")
    lines.append(r"\makeatother")
    (OUT / "numbers.tex").write_text("\n".join(lines) + "\n")
    print(f"{len(defs)} number keys; tab_main.tex; fig_main.pdf")


if __name__ == "__main__":
    main()
