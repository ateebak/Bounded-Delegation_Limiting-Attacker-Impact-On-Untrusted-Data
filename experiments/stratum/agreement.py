"""Validate annotation files and compute A-vs-B agreement for the pilot (D-007).

  --validate-only   check B/*.json (and A_sealed/*.json if present) against annotations/schema.json.
  (default)         also verify A_sealed files against the committed hashes in A_sealed.sha256,
                    then report, for each annotator pair (A-B, A-C, B-C where present), per-field raw
                    agreement and Cohen's kappa over matched (task, call, arg) fields, plus
                    stratum_decision agreement. Output: annotations/agreement_pilot.json.
C is an AI annotator (Codex, gpt-6.1-sol), run blind in an isolated workspace (see annotations/C_run/).
Fields present for only one annotator are listed (coverage disagreement) and excluded from kappa.
"""
import collections, hashlib, json, pathlib, sys
import jsonschema

ANN = pathlib.Path(__file__).resolve().parent / "annotations"
SCHEMAS = {"v0.3": json.loads((ANN / "schema_v03.json").read_text()), "v0.4": json.loads((ANN / "schema_v04.json").read_text())}
CATEGORICAL = ["delegation_explicitness", "attacker_can_write_value", "trusted_corroboration_available", "param_role",
               "harm_if_attacker_controlled", "reversible", "fixture_validity",
               "clarification_intrinsic", "clarification_nosuspicion", "clarification_cautious"]  # v0.3 has the first; v0.4 the last two


def load(dirname):
    out = {}
    for f in sorted((ANN / dirname).glob("*.json")):
        rec = json.loads(f.read_text())
        jsonschema.validate(rec, SCHEMAS[rec.get("handbook_version", "v0.3")])
        out[rec["task_key"]] = rec
    return out


def verify_seal(which="A"):
    bad = []
    for line in (ANN / f"{which}_sealed.sha256").read_text().splitlines():
        h, name = line.split()
        p = ANN / f"{which}_sealed" / name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != h: bad.append(name)
    if bad: raise SystemExit(f"{which}_sealed hash mismatch or missing: {bad}. Agreement not computed.")


def kappa(pairs):
    n = len(pairs)
    if n == 0: return None
    po = sum(a == b for a, b in pairs) / n
    ca, cb = collections.Counter(a for a, _ in pairs), collections.Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return None if pe == 1 else round((po - pe) / (1 - pe), 3)


def compare(X, Y):
    common = sorted(set(X) & set(Y))
    fx = {(k, f["call"], f["arg"]): f for k in common for f in X[k]["fields"]}
    fy = {(k, f["call"], f["arg"]): f for k in common for f in Y[k]["fields"]}
    matched = sorted(set(fx) & set(fy))
    rep = {"tasks_compared": common, "fields_matched": len(matched),
           "only_first": [list(x) for x in sorted(set(fx) - set(fy))], "only_second": [list(x) for x in sorted(set(fy) - set(fx))],
           "stratum_decision_agreement": sum(X[k]["stratum_decision"] == Y[k]["stratum_decision"] for k in common) / max(len(common), 1),
           "per_field": {}}
    for c in CATEGORICAL:
        pairs = [(fx[m][c], fy[m][c]) for m in matched if c in fx[m] and c in fy[m]]
        if not pairs: continue
        rep["per_field"][c] = {"n": len(pairs), "raw_agreement": round(sum(a == b for a, b in pairs) / max(len(pairs), 1), 3),
                               "cohen_kappa": kappa(pairs),
                               "disagreements": [[*m, fx[m][c], fy[m][c]] for m in matched if fx[m][c] != fy[m][c]]}
    return rep


def main():
    sets = {}
    sub = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--round=")), "")  # e.g. --round=v04 -> B_v04, C_v04_sealed, A_v04_sealed
    suf = f"_{sub}" if sub else ""
    for name, d in (("B", f"B{suf}"), ("C", f"C{suf}_sealed")):
        if (ANN / d).exists(): sets[name] = load(d); print(f"{name}: {len(sets[name])} valid files")
    if "--validate-only" in sys.argv:
        if (ANN / f"A{suf}_sealed").exists(): print(f"A: {len(load(f'A{suf}_sealed'))} valid files (sealed)")
        return
    verify_seal(f"A{suf}"); verify_seal(f"C{suf}")
    sets["A"] = load(f"A{suf}_sealed")
    report = {}
    for x, y in (("A", "B"), ("A", "C"), ("B", "C")):
        if sets.get(x) and sets.get(y):
            r = report[f"{x}-{y}"] = compare(sets[x], sets[y])
            print(f"== {x}-{y}: tasks={len(r['tasks_compared'])} matched fields={r['fields_matched']} "
                  f"stratum agreement={r['stratum_decision_agreement']:.2f}")
            for c, v in r["per_field"].items():
                print(f"  {c:34s} n={v['n']:3d} agree={v['raw_agreement']:.2f} kappa={v['cohen_kappa']}")
    (ANN / f"agreement{suf or '_pilot'}.json").write_text(json.dumps(report, indent=1) + "\n")


if __name__ == "__main__":
    main()
