"""Heuristic first pass for the delegated-authority stratum (Week 2).

For every user task in AgentDojo-lineage suites (AgentDyn checkout, benchmark v1.2.2),
inspect the ground-truth calls to state-changing tools. An argument is a *delegation
candidate* when its value does not occur in the user prompt, so the agent must obtain it
from environment content that an attacker may be able to write.

This is only a screening heuristic. Values can be derived without literal overlap
(e.g. "my landlord" -> an IBAN from a trusted record), and literal overlap can be
coincidental. Every candidate needs manual annotation (docs/annotation-handbook.md).
No model is called; output is deterministic given the pinned checkout.

Usage: .venv/bin/python experiments/stratum/find_delegated_candidates.py
"""
import csv, json, pathlib, re, subprocess
from agentdojo.task_suite.load_suites import get_suites

VERSION = "v1.2.2"
OUT = pathlib.Path(__file__).resolve().parent

# Curated from the tool lists of all seven suites. Read-only tools are excluded.
STATE_CHANGING = {
    "send_money", "schedule_transaction", "update_scheduled_transaction", "update_password",
    "update_user_info", "send_email", "delete_email", "create_calendar_event",
    "add_calendar_event_participants", "cancel_calendar_event", "reschedule_calendar_event",
    "create_file", "append_to_file", "delete_file", "share_file", "reserve_hotel",
    "reserve_restaurant", "reserve_car_rental", "send_direct_message", "send_channel_message",
    "invite_user_to_slack", "add_user_to_channel", "remove_user_from_slack", "post_webpage",
    "cart_add_product", "cart_remove_product", "checkout_selected_cart", "clear_cart",
    "refund_order", "update_shopping_account_password", "update_shopping_account_user_info",
    "input_to_webpage", "download_file_through_url", "download_file_through_id", "copy_node",
    "move_node", "delete_node", "create_dir", "git_add_ssh_key", "git_delete_ssh_key",
    "git_clone", "git_create_repo", "git_delete_repo", "git_invite_collaborators", "git_issue",
    "git_push", "git_star", "git_unstar", "git_transfer_repo_ownership",
    "update_github_account_password", "verify_transaction",
}
DESTINATION = re.compile(r"recipient|^to$|email|cc|bcc|participant|user$|channel|url|owner|collaborator|iban|address")
MAGNITUDE = re.compile(r"amount|price|quantity|count")
FREE_TEXT = re.compile(r"body|subject|content|message|description|title|text")


def param_class(name: str) -> str:
    n = name.lower()
    if MAGNITUDE.search(n): return "magnitude"
    if FREE_TEXT.search(n): return "free_text"
    if DESTINATION.search(n): return "destination"
    return "identifier_or_other"


def leaves(v):
    if isinstance(v, (list, tuple)):
        for x in v: yield from leaves(x)
    elif isinstance(v, dict):
        for x in v.values(): yield from leaves(x)
    elif v is not None and not isinstance(v, bool):
        yield v


def in_prompt(value, prompt: str) -> bool:
    p = prompt.lower()
    if isinstance(value, (int, float)):
        forms = {str(value), f"{value:g}", f"{value:,.2f}", f"{value:.2f}"}
        return any(f.lower() in p for f in forms)
    s = str(value).strip().lower()
    return bool(s) and s in p


def flatten(obj, path=""):
    """path -> string for every scalar leaf of a JSON-dumped environment."""
    if isinstance(obj, dict):
        for k, v in obj.items(): yield from flatten(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj): yield from flatten(v, f"{path}[{i}]")
    elif obj is not None:
        yield path, str(obj)


def value_forms(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return {f for f in {str(value), f"{value:g}", f"{value:.2f}", f"{value:,.2f}"} if len(f) >= 3}
    s = str(value).strip()
    return {s} if len(s) >= 3 else set()  # ignore very short strings (too many spurious hits)


def origin_class(value, default_leaves, writable_paths):
    """Where does a ground-truth value occur in the default environment?

    attacker_only: only inside fields that hold an injection vector (attacker can replace it)
    mixed: in an attacker-writable field and in a trusted field (corroboration is possible)
    trusted_only: only in fields without an injection vector
    not_found: derived or computed (needs manual annotation)
    """
    forms = value_forms(value)
    if not forms: return "not_found"
    hits = {p for p, s in default_leaves.items() if any(f.lower() in s.lower() for f in forms)}
    if not hits: return "not_found"
    w = hits & writable_paths
    if w and w == hits: return "attacker_only"
    if w: return "mixed"
    return "trusted_only"


def main():
    rows, per_task = [], {}
    for sname, suite in get_suites(VERSION).items():
        defaults = suite.get_injection_vector_defaults()
        canary_env = suite.load_and_inject_default_environment({k: f"CANARY::{k}" for k in defaults})
        default_env = suite.load_and_inject_default_environment(defaults)
        canary_leaves = dict(flatten(canary_env.model_dump(mode="json")))
        default_leaves = dict(flatten(default_env.model_dump(mode="json")))
        writable_paths = {p for p, s in canary_leaves.items() if "CANARY::" in s}
        for tid, task in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment(defaults)
            try:
                calls = task.ground_truth(env.model_copy(deep=True))
            except Exception as e:  # record, don't hide
                per_task[(sname, tid)] = {"error": repr(e)}
                continue
            prompt = task.PROMPT
            deleg = []
            for c in calls:
                if c.function not in STATE_CHANGING: continue
                for arg, val in (c.args or {}).items():
                    vals = list(leaves(val))
                    if not vals: continue
                    missing = [v for v in vals if not in_prompt(v, prompt)]
                    cls = param_class(arg)
                    origins = sorted({origin_class(v, default_leaves, writable_paths) for v in missing})
                    rows.append(dict(suite=sname, task=tid, tool=c.function, arg=arg, param_class=cls,
                                     value=json.dumps(val, default=str)[:200],
                                     in_prompt=not missing, delegated_candidate=bool(missing),
                                     origin="|".join(origins)))
                    if missing and cls in ("destination", "magnitude", "identifier_or_other") \
                            and ({"attacker_only", "mixed"} & set(origins)):
                        deleg.append(f"{c.function}.{arg}[{'|'.join(origins)}]")
            per_task[(sname, tid)] = {"prompt": prompt, "sensitive_delegated_args": sorted(set(deleg))}
    with open(OUT / "delegated_candidates_args.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    commit = subprocess.run(["git", "-C", str(pathlib.Path(__file__).resolve().parents[2] / "external/AgentDyn"),
                             "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    summary = {"benchmark_version": VERSION, "agentdyn_commit": commit, "suites": {}}
    for (s, t), d in per_task.items():
        e = summary["suites"].setdefault(s, {"tasks": 0, "with_sensitive_delegation": 0, "errors": 0, "candidates": {}})
        e["tasks"] += 1
        if "error" in d: e["errors"] += 1; continue
        if d["sensitive_delegated_args"]:
            e["with_sensitive_delegation"] += 1
            e["candidates"][t] = {"args": d["sensitive_delegated_args"], "prompt": d["prompt"]}
    (OUT / "delegated_candidates_summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    for s, e in summary["suites"].items():
        print(f"{s:10s} tasks={e['tasks']:3d} attacker-reachable sensitive delegation={e['with_sensitive_delegation']:3d} errors={e['errors']}")


if __name__ == "__main__":
    main()
