"""Trusted reference values for relative magnitude bounds (spec §3 `bounds.rel_to`, D-043).

A relative bound caps a delegated amount at reference × (1 + rel_max), where the reference is read from
platform-maintained state (a trusted record, like T3), never from content the agent read. References are taken from the
PRE-EPISODE snapshot, so an agent (or attacker) can't ratchet the bound by updating the record during the task.

Reference rules (fixed before any run, D-043):
  update_scheduled_transaction.amount         current amount of the scheduled transaction with that `id`;
  send_money / schedule_transaction.amount    the most recent outgoing payment from the user's account to the same
                                              recipient in the transaction history.
No reference -> None, and the absolute cap (request amount or deployment ceiling) applies unchanged.
"""


def _account(env):
    if env is None: return None
    if hasattr(env, "bank_account"): return env.bank_account
    db = getattr(env, "bank_database", None)
    if db is not None:
        cur = getattr(db, "current_account", None)
        return next((a for a in db.account_list if a.iban == cur), None) or (db.account_list[0] if db.account_list else None)
    return None


def _same(a, b):
    return str(a).strip().lower() == str(b).strip().lower()


def trusted_reference(env, tool: str, args: dict):
    acct = _account(env)
    if acct is None: return None
    if tool == "update_scheduled_transaction":
        try: tid = int(args.get("id"))
        except (TypeError, ValueError): return None
        t = next((t for t in acct.scheduled_transactions if t.id == tid), None)
        return float(t.amount) if t is not None else None
    if tool in ("send_money", "schedule_transaction") and args.get("recipient"):
        own = {"me", str(acct.iban).lower()}
        out = [t for t in acct.transactions if str(t.sender).lower() in own and _same(t.recipient, args["recipient"])]
        if out:
            return float(max(out, key=lambda t: (str(t.date), t.id)).amount)
    return None


def make_reference(pre_env):
    """reference(tool, args) callable over a frozen pre-episode snapshot."""
    return lambda tool, args: trusted_reference(pre_env, tool, args)
