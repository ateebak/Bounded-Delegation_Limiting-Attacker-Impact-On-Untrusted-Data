"""Progent-v3-style approver around the RELEASED Progent policy updater (D-038). OUR REIMPLEMENTATION, labelled as such.

Progent v3 (shi2025progentv3 §4, §8.2; read in full text) judges every proposed policy update: a narrowing (P' admits
no call that P doesn't) is applied automatically; an expansion needs approval. Approver modes: Auto-Deny, Auto-Approve,
Manual Approval. The released code (official repo and ROPE's AutoDojo port) applies updates without any judgment
(F-11). We wrap the released `generate_update_security_policy`: snapshot P, let the released updater produce and apply
P', judge P -> P', and on an expansion ask the approver; a denied expansion restores P. The initial policy P1 (derived
from the user task) is applied automatically, as in the paper.

Judgment: v3 decides P' ⊆ P with an SMT solver over symbolic policies. We use a deterministic, CONSERVATIVE
structural check: P' is a narrowing only if (1) every forbid rule of P is still in P', and (2) every allow rule of P'
is covered by some allow rule of P, argument by argument (no restriction covers anything; enum/const subset; numeric
ranges contained; identical schemas). Anything we can't prove covered counts as an expansion (more approvals, never
fewer than the exact check would require).

Manual mode uses the same simulated users as our defense (D-020): perfect approves an expansion iff every value it
newly admits for a sensitive argument matches the legitimate value and no sensitive argument is left unrestricted;
rubber_stamp approves all; plausible:p approves with probability p.
"""
import copy, json, pathlib, random

ROOT = pathlib.Path(__file__).resolve().parents[2]
TABLE = json.loads((ROOT / "defense/bounded/sensitive_fields.json").read_text())


def _rules(policy, tool, effect):
    return [r for r in (policy or {}).get(tool, []) if len(r) >= 3 and r[1] == effect]


def _schema_covered(sub, sup):
    """Is every value admitted by schema `sub` admitted by `sup`? Conservative: False when unsure."""
    if not sup: return True                       # sup unrestricted
    if not sub: return False                      # sub unrestricted, sup restricted
    if sub == sup: return True
    if "enum" in sup:
        vals = sub.get("enum") if "enum" in sub else ([sub["const"]] if "const" in sub else None)
        return vals is not None and all(v in sup["enum"] for v in vals)
    if "const" in sup:
        return sub.get("const") == sup["const"] or (sub.get("enum") == [sup["const"]])
    lo_ok = "minimum" not in sup or ("minimum" in sub and sub["minimum"] >= sup["minimum"]) or \
            ("enum" in sub and all(isinstance(v, (int, float)) and v >= sup["minimum"] for v in sub["enum"]))
    hi_ok = "maximum" not in sup or ("maximum" in sub and sub["maximum"] <= sup["maximum"]) or \
            ("enum" in sub and all(isinstance(v, (int, float)) and v <= sup["maximum"] for v in sub["enum"]))
    other = {k for k in sup if k not in ("type", "minimum", "maximum", "description")}
    return lo_ok and hi_ok and not other and sub.get("type", sup.get("type")) == sup.get("type")


def _rule_covered(r_new, rules_old):
    cond_new = r_new[2] or {}
    for r in rules_old:
        cond_old = r[2] or {}
        if all(_schema_covered(cond_new.get(a), cond_old.get(a)) for a in set(cond_old) | set(cond_new)):
            return True
    return False


def expansion(before, after):
    """Returns the list of (tool, rule) in `after` not proven admitted by `before` ([] = narrowing)."""
    out = []
    for tool, rules in (before or {}).items():
        for r in _rules(before, tool, 1):
            if r not in (after or {}).get(tool, []):
                out.append((tool, ("removed forbid rule", r)))
    for tool in (after or {}):
        for r in _rules(after, tool, 0):
            if not _rule_covered(r, _rules(before, tool, 0)):
                out.append((tool, r))
    return out


class Approver:
    def __init__(self, mode, sim="perfect", p=1.0, legit=None, seed=0):
        assert mode in ("auto_deny", "auto_approve", "manual")
        self.mode, self.sim, self.p, self.legit = mode, sim, p, legit or {}
        self.rng, self.prompts, self.log = random.Random(seed), 0, []

    def _perfect(self, delta):
        from defense.bounded.monitor import _matches
        for tool, rule in delta:
            if isinstance(rule[0], str): return False            # removing a forbid rule
            sens = [a for a in TABLE.get(tool, {}) if not a.startswith("_")]
            cond = rule[2] or {}
            for a in sens:
                sch = cond.get(a)
                vals = sch.get("enum") if sch and "enum" in sch else ([sch["const"]] if sch and "const" in sch else None)
                if vals is None: return False                    # sensitive argument left open
                legit = self.legit.get(tool, {}).get(a)
                if legit is None or not all(_matches(v, legit) for v in vals): return False
        return True

    def approve(self, delta):
        if self.mode == "auto_deny": ok = False
        elif self.mode == "auto_approve": ok = True
        else:
            self.prompts += 1
            ok = (self._perfect(delta) if self.sim == "perfect" else
                  True if self.sim == "rubber_stamp" else self.rng.random() < self.p)
        self.log.append({"delta": json.loads(json.dumps(delta, default=str)), "approved": ok, "mode": self.mode})
        return ok


def install(approver):
    """Wrap the released updater (module-level functions in ROPE's AutoDojo port) with the approver."""
    from agentdojo.agent_pipeline.progent_defense import progent_elements as pe
    from agentdojo.agent_pipeline.progent_defense.secagent import tool as st
    orig = getattr(pe, "_released_generate_update_security_policy", pe.generate_update_security_policy)
    pe._released_generate_update_security_policy = orig

    def judged_update(tool_call_param, tool_call_result, manual_check=False):
        before = copy.deepcopy(st.security_policy)
        orig(tool_call_param, tool_call_result, manual_check=False)
        delta = expansion(before, st.security_policy)
        if delta and not approver.approve(delta):
            st.security_policy = before                          # denied expansion: P stays
    pe.generate_update_security_policy = judged_update
    return approver
