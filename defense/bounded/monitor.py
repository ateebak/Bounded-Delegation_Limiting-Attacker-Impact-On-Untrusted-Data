"""Bounded-delegation monitor (spec §5, D-020) and confirmation simulators.

decide(tool, args) -> Decision(code, action), where action is execute | stage | deny.
Codes: allowed, allowed_staged, deferred_confirmation (approved by the simulator), denied_origin, denied_envelope.
(`attenuated` from the spec isn't produced yet: on_violation is `defer` for all fields in this version.)
Per sensitive argument value v:
  trusted origin (T1 request or T3 record)          -> ok
  delegated by the envelope and from untrusted read -> check bounds (amount <= abs_max), once, family cap
  otherwise                                         -> denied_origin
Non-payment rule (D-020): one message or invite per task (family cap); STAGE if the call carries attachments or
grants write access (share_file permission 'rw', git_invite_collaborators). Payments: mode A executes within the
cap; mode B stages every delegated payment. Envelope violations defer to the confirmation simulator; origin
violations are denied outright (no confirmation path).
State only narrows: `once` and family counters are consumed when an effect actually executes or is staged.
"""
import random, re
from dataclasses import dataclass

from .envelope import TABLE, FieldEnvelope, TaskEnvelope, never_delegable
from .origin import OriginTracker

TRUSTED = {"T1", "T3"}


@dataclass
class Decision:
    code: str
    action: str          # execute | stage | deny
    detail: str = ""


def _scalars(v):
    if isinstance(v, (list, tuple)):
        for x in v: yield from _scalars(x)
    elif isinstance(v, dict):
        for x in v.values(): yield from _scalars(x)
    elif v is not None:
        yield v


def _matches(actual, legit) -> bool:
    """Value equality tolerant of number formatting and of a legit scalar inside a list argument (recipients)."""
    vals = list(_scalars(actual))
    if not vals: return False
    def norm(x):  # same URL with/without scheme or trailing slash is the same value (D-036)
        t = str(x).strip().lower()
        t = re.sub(r"^https?://", "", t)
        return t[:-1] if t.endswith("/") else t
    def eq(x, y):
        try: return abs(float(x) - float(y)) < 1e-6
        except (TypeError, ValueError): return norm(x) == norm(y)
    legits = list(_scalars(legit))
    return all(any(eq(v, l) for l in legits) for v in vals)


class ConfirmationSimulator:
    """Simulated user answering a deferred confirmation (D-020: report all three)."""

    def __init__(self, kind: str, p: float = 1.0, gold_values: dict | None = None, seed: int = 0):
        if kind not in ("perfect", "rubber_stamp", "plausible"): raise ValueError(kind)
        self.kind, self.p, self.gold, self.rng = kind, p, gold_values or {}, random.Random(seed)
        self.prompts = 0

    def approve(self, tool: str, args: dict) -> bool:
        self.prompts += 1
        if self.kind == "rubber_stamp": return True
        if self.kind == "perfect":  # approves iff every SENSITIVE field matches the legitimate value (non-sensitive
            # fields such as date/subject are the agent's choice; fixed 2026-10-01, previously compared all fields)
            sens = {a for a in TABLE.get(tool, {}) if not a.startswith("_")}
            gold = {a: v for a, v in self.gold.get(tool, {}).items() if a in sens}
            return bool(gold) and all(_matches(args.get(a), v) for a, v in gold.items())
        return self.rng.random() < self.p  # plausible-p: approves well-formed proposals with probability p


class BoundedMonitor:
    def __init__(self, envelope: TaskEnvelope, tracker: OriginTracker, simulator: ConfirmationSimulator,
                 commit_on_success: bool = False, escalate_unlisted: bool = False, hard_caps: bool = False,
                 reference=None, rel_max: float | None = None, rel_mode: str = "replace", ask_family=None):
        """commit_on_success (D-031): once/family/aggregate bookkeeping for an EXECUTED call is applied only when the
        caller reports success via commit(); a failed call (tool error) leaves no effect, so a retry isn't a second
        use. Staged actions count at decision time (staging is the effect). Record-closure taint is always applied
        at decision time (conservative). Default False = bookkeeping at decision time (unit-test semantics)."""
        self.env, self.tracker, self.sim = envelope, tracker, simulator
        self.used_once, self.family_count, self.log = set(), {}, []
        self.paid_total = 0.0  # cumulative executed delegated payment amount this task (aggregate bound, spec §3)
        self.commit_on_success, self._pending = commit_on_success, {}
        # D-035: an untrusted value for a sensitive field the envelope doesn't list is put to the user ONCE instead of
        # being denied. Approved -> the field joins the envelope (caps/once/family limits apply from then on);
        # rejected -> that value is refused without asking again. False = fail-closed (D-020 behaviour; ablation).
        self.escalate_unlisted, self.rejected = escalate_unlisted, set()
        # D-039: hard caps. Cap violations (amount/aggregate over the cap, second use of a once value, family limit) are
        # DENIED without asking: a confirming user can't override them (F-21: rubber-stamp users approved 12,356 over a
        # 500 cap). Only soft conditions (field outside the envelope, missing corroboration) go to the user.
        # False = soft caps (confirmable; D-020 behaviour, ablation).
        self.hard_caps = hard_caps
        # D-043: relative bounds (spec §3 rel_to/rel_max). When `reference(tool, args)` returns a trusted reference
        # amount (pre-episode platform state, reference.py), the amount cap for that call is reference × (1 + rel_max)
        # INSTEAD of the deployment ceiling (it can be lower or higher). An amount stated in the request still wins.
        # None = absolute caps only (D-020 behaviour; ablation).
        self.reference, self.rel_max = reference, rel_max
        # D-052 (post-hoc ablation, D-051): rel_mode "max" takes the LARGER of the relative cap and the deployment cap
        # (max(ceiling, rel)) instead of replacing it ("replace", the preregistered D-043 rule).
        if rel_mode not in ("replace", "max"): raise ValueError(rel_mode)
        self.rel_mode = rel_mode
        # D-052 (post-hoc ablation, D-051): ask-family limits {family: n}. A delegated use of these families beyond
        # the n-th per task goes to the user (a SOFT condition, confirmable even under hard caps) instead of executing.
        # Values named in the request (trusted origin) are not delegated uses and are never counted. Targets the
        # F-A5 download fan-out without hard-denying tasks that legitimately need two (dailylife ut14). None = off.
        self.ask_family = dict(ask_family or {})

    def _eff_cap(self, tool, args, cap):
        if cap is None or self.rel_max is None or self.reference is None or self.env.request_cap is not None:
            return cap
        ref = self.reference(tool, args)
        if ref is None: return cap
        rel = round(ref * (1 + self.rel_max), 2)
        return max(cap, rel) if self.rel_mode == "max" else rel

    def commit(self, tool, args, ok: bool):
        """Report the outcome of an executed call (only meaningful with commit_on_success)."""
        key = (tool, repr(sorted((k, repr(v)) for k, v in args.items())))
        if self._pending.pop(key, False) and ok:
            self._count(tool, args, "execute")

    def _count(self, tool, args, action):
        fam = TABLE.get(tool, {}).get("_family")
        self.family_count[fam] = self.family_count.get(fam, 0) + 1
        for arg in TABLE.get(tool, {}):
            if not arg.startswith("_") and (tool, arg) in self.env.fields and self.env.fields[(tool, arg)].once:
                for v in _scalars(args.get(arg)): self.used_once.add((tool, arg, str(v)))
        if fam == "payment" and action == "execute":
            try: self.paid_total += float(args.get("amount") or 0)
            except (TypeError, ValueError): pass

    def _finish(self, tool, args, d: Decision, delegated: bool = False) -> Decision:
        if d.action in ("execute", "stage") and delegated:  # caps count delegated effects only (D-020)
            if d.action == "execute" and self.commit_on_success:
                self._pending[(tool, repr(sorted((k, repr(v)) for k, v in args.items())))] = True
            else:
                self._count(tool, args, d.action)
        if d.action in ("execute", "stage"):  # record closure: everything this effect writes stays untrusted
            for arg in TABLE.get(tool, {}):
                if not arg.startswith("_"):
                    for v in _scalars(args.get(arg)): self.tracker.note_written(v)
        self.log.append({"tool": tool, "args": args, "code": d.code, "action": d.action, "detail": d.detail})
        return d

    def decide(self, tool: str, args: dict) -> Decision:
        spec = TABLE.get(tool)
        if spec is None:
            return Decision("allowed", "execute", "non-sensitive tool")
        fam = spec.get("_family")
        delegated_used, violation, unlisted, capv = False, None, [], []
        for arg, role in spec.items():
            if arg.startswith("_") or args.get(arg) in (None, [], ""): continue
            fe = self.env.get(tool, arg)
            for v in _scalars(args[arg]):
                org = self.tracker.origin(v)
                if org & TRUSTED and not (role == "magnitude" and fe is not None):
                    continue
                if fe is None:
                    if org & TRUSTED: continue
                    if not self.escalate_unlisted:
                        return self._finish(tool, args, Decision("denied_origin", "deny", f"{arg}={v!r} origin={sorted(org)}"))
                    if (tool, arg, str(v)) in self.rejected:
                        return self._finish(tool, args, Decision("denied_rejected", "deny", f"{arg}={v!r} already rejected by the user"))
                    unlisted.append((arg, role, v))
                    violation = violation or f"{arg}={v!r} outside the envelope (origin={sorted(org)})"
                    delegated_used = True
                    continue
                delegated_used = True
                if fe.corroborate and "T3" not in org:
                    violation = violation or f"{arg}={v!r} not corroborated by a trusted record"
                if (tool, arg, str(v)) in self.used_once:
                    capv.append(f"{arg} already used once")
                if role == "magnitude" and fe.abs_max is not None:
                    try:
                        c = self._eff_cap(tool, args, fe.abs_max)
                        if float(v) > c: capv.append(f"{arg}={v} > cap {c}")
                    except (TypeError, ValueError):
                        pass
        if delegated_used and fam == "payment":
            fe_amt = self.env.get(tool, "amount")
            try: amt = float(args.get("amount") or 0)
            except (TypeError, ValueError): amt = 0.0
            c = self._eff_cap(tool, args, fe_amt.abs_max) if fe_amt is not None else None
            if c is not None and self.paid_total + amt > c:
                capv.append(f"aggregate {self.paid_total + amt:g} > cap {c} (split payments count together)")
        cap = self.env.family_cap.get(fam)
        if delegated_used and cap is not None and self.family_count.get(fam, 0) >= cap:
            capv.append(f"family '{fam}' per-task cap {cap} reached")
        acap = self.ask_family.get(fam)
        if delegated_used and acap is not None and self.family_count.get(fam, 0) >= acap:
            violation = violation or f"family '{fam}': delegated use beyond {acap} per task (ask)"
        if unlisted:  # caps that would apply once the field is delegated (amount ceiling / request cap)
            cap = self._eff_cap(tool, args, self.env.request_cap if self.env.request_cap is not None else self.env.ceiling)
            for arg, role, v in unlisted:
                if role == "magnitude" and cap is not None:
                    try:
                        if float(v) > cap: capv.append(f"{arg}={v} > cap {cap}")
                    except (TypeError, ValueError): pass
        if capv and self.hard_caps:
            for arg, role, v in unlisted: self.rejected.add((tool, arg, str(v)))
            return self._finish(tool, args, Decision("denied_cap", "deny", "; ".join(capv) + " (hard cap, not confirmable)"))
        if capv:
            violation = "; ".join(([violation] if violation else []) + capv)
        if violation:
            if self.sim.approve(tool, args):  # one prompt covers everything wrong with this call
                for arg, role, v in unlisted:
                    if never_delegable(tool): continue  # D-044: approving one credential value doesn't delegate the field
                    cap = self.env.request_cap if self.env.request_cap is not None else self.env.ceiling
                    self.env.fields[(tool, arg)] = FieldEnvelope(tool, arg, role, delegated=True,
                                                                 abs_max=cap if role == "magnitude" else None)
                return self._finish(tool, args, Decision("deferred_confirmation", "execute", violation + "; approved"), delegated_used)
            for arg, role, v in unlisted: self.rejected.add((tool, arg, str(v)))
            return self._finish(tool, args, Decision("denied_envelope", "deny", violation + "; not approved"))
        grants_write = (tool == "share_file" and str(args.get("permission", "")).lower() in ("rw", "w", "write", "edit")) \
            or tool == "git_invite_collaborators"
        if delegated_used and (bool(args.get("attachments")) or grants_write):
            return self._finish(tool, args, Decision("allowed_staged", "stage", "attachment or write access"), delegated_used)
        if delegated_used and fam == "payment" and self.env.mode == "B":
            return self._finish(tool, args, Decision("allowed_staged", "stage", "mode B"), delegated_used)
        return self._finish(tool, args, Decision("allowed", "execute", "delegated within envelope" if delegated_used else "trusted origin"), delegated_used)
