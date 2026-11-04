"""Origin tracker (spec §5). Value-matching provenance in the spirit of ROPE's origin tracker (MIT), simplified.

Every tool output the agent sees is recorded as a READ with an origin class:
  T3  trusted record: platform-maintained state (TRUSTED_READ_TOOLS), plus platform sender headers of emails;
  U   untrusted content: every other read (fail-safe default).
The user request is origin T1. origin(v) returns the set of classes whose text contains v (normalised).
A value matching nothing is 'agent' (model-generated), treated as untrusted.
"""
import re

TRUSTED_READ_TOOLS = {
    "get_balance", "get_iban", "get_most_recent_transactions", "get_scheduled_transactions", "get_user_info",
    "get_channels", "get_users_in_channel", "get_current_day", "search_contacts_by_name", "search_contacts_by_email",
    "get_github_repository_information", "get_logged_in_github_user_information", "get_github_account_user_information",
    "view_order_history", "get_shopping_account_user_information", "view_cart", "cart_total",
    "get_all_hotels_in_city", "get_all_restaurants_in_city", "get_all_car_rental_companies_in_city",
}
SENDER_RE = re.compile(r"\bsender:\s*([^\s|,'\"]+)")
NUM_RE = re.compile(r"(?<![\w.])-?\d+(?:[.,]\d+)?")


def norm(v) -> str:
    return re.sub(r"\s+", " ", str(v)).strip().lower()


def _numbers(text: str) -> set:
    out = set()
    for m in NUM_RE.findall(text):
        try: out.add(round(float(m.replace(",", "")), 4))
        except ValueError: pass
    return out


class OriginTracker:
    def __init__(self, request: str):
        self.request = request
        self.reads = []  # list of (origin_class, source_label, text)
        self.written = set()  # normalised values written by effects executed in THIS episode (record closure)

    def note_written(self, value) -> None:
        """Record closure (cf. ROPE Lemma 1): a value the agent itself wrote into a record (e.g. a payee now in the
        transaction history) must not GAIN T3 trust when read back. Only values that were untrusted at write time are
        recorded: a value that already had trusted origin (request T1 or trusted record T3) keeps it (D-031; before,
        writing a trusted recipient into a sent email made that recipient untrusted for the rest of the task, F-18)."""
        if self.origin(value) & {"T1", "T3"}:
            return
        self.written.add(norm(value) if not isinstance(value, (int, float)) or isinstance(value, bool) else round(float(value), 4))

    def record_read(self, tool: str, args: dict, text: str) -> None:
        cls = "T3" if tool in TRUSTED_READ_TOOLS else "U"
        self.reads.append((cls, f"{tool}({args})", text))
        if cls == "U":  # platform sender headers inside email listings are trusted (spec §2)
            for s in SENDER_RE.findall(text):
                self.reads.append(("T3", f"{tool}:sender_header", s))

    def origin(self, value) -> set:
        """Origin classes for one scalar value (lists: call per element)."""
        found = set()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            target = round(float(value), 4)
            if target in _numbers(self.request): found.add("T1")
            for cls, _, text in self.reads:
                if target in _numbers(text): found.add(cls)
        else:
            v = norm(value)
            if len(v) < 3: return {"T1"}  # trivially short values carry no provenance signal
            if v in norm(self.request): found.add("T1")
            for cls, _, text in self.reads:
                if v in norm(text): found.add(cls)
        key = round(float(value), 4) if isinstance(value, (int, float)) and not isinstance(value, bool) else norm(value)
        if key in self.written and "T1" not in found:
            found.discard("T3"); found.add("U_laundered")  # read back from a record the agent wrote: not trusted
        return found or {"agent"}

    def sources(self, value) -> list:
        v = norm(value)
        return [lbl for cls, lbl, text in self.reads if cls == "U" and v in norm(text)]
