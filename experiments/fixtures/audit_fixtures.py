"""Fixture audit (D-015): find malformed or implausible values in benchmark environments and tasks.

Scans every suite of the pinned AgentDyn checkout (benchmark v1.2.2 data plus all default_suites
versions): environment YAML, injection-vector defaults, and user/injection task code.
Checks:
  iban      IBAN-like tokens: ISO 13616 mod-97 checksum, known country code, country length.
  email     syntax (local@domain.tld) and hostname rules.
  url       hostnames with characters invalid in DNS (e.g. '_').
  date      YYYY-MM-DD strings that aren't real dates.
  currency  bill/payment texts with an amount but no currency marker.
Each finding records role = legitimate | attacker | both (attacker if the value occurs in an
injection_tasks.py), plus the files it occurs in.
Output: experiments/fixtures/fixture_audit.json. Deterministic; no model calls.
"""
import collections, datetime, json, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2]
import os
AD = ROOT / os.environ.get("AUDIT_TREE", "external/AgentDyn") / "src/agentdojo"
OUT = pathlib.Path(__file__).resolve().parent / os.environ.get("AUDIT_OUT", "fixture_audit.json")
# ISO 13616 registry lengths for countries that occur here or are used as replacements
IBAN_LEN = {"AT": 20, "BE": 16, "CH": 21, "CZ": 24, "DE": 22, "DK": 18, "ES": 24, "FR": 27, "GB": 22, "IE": 22,
            "IT": 27, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "SE": 24, "CF": 27}
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}\d{2}[A-Z0-9]{8,30})(?![A-Za-z0-9])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9._\-]+")
URL_RE = re.compile(r"(?:https?://)?(www\.[A-Za-z0-9_\-.]+\.[a-z]{2,})")
DATE_RE = re.compile(r"(?<!\d)(\d{4})-(\d{2})-(\d{2})(?!\d)")
AMOUNT_TXT_RE = re.compile(r"(amount due|total|please pay|payment of|pay the amount)[^\n]{0,80}?(\d+[.,]\d{2})", re.I)
CURRENCY_RE = re.compile(r"[$€£¥]|\b(EUR|USD|GBP|CHF|SEK|dollars?|euros?|pounds?)\b", re.I)
SUITES = ["banking", "slack", "travel", "workspace", "shopping", "github", "dailylife"]


def iban_issue(tok):
    cc = tok[:2]
    if cc not in IBAN_LEN and cc not in ("US", "UK", "CA", "DH", "CS"):
        pass
    if cc in ("UK",): return "iban_country_code_not_iso"  # GB is the ISO code
    if cc in ("US", "CA"): return "iban_country_has_no_iban"
    if cc not in IBAN_LEN: return "iban_unknown_country"
    if len(tok) != IBAN_LEN[cc]: return "iban_length"
    n = int("".join(str(int(c, 36)) for c in tok[4:] + tok[:4]))
    return None if n % 97 == 1 else "iban_checksum"


def files_for(suite):
    fs = list((AD / "data/suites" / suite).rglob("*.yaml"))
    fs += [p for p in (AD / "default_suites").glob(f"*/{suite}*/*.py")]  # also ROPE's banking_v2_*, travel_v2_* variants
    return fs


def main():
    findings = collections.defaultdict(lambda: {"files": set(), "roles": set()})
    for suite in SUITES:
        for f in files_for(suite):
            text = f.read_text(errors="ignore")
            rel = str(f.relative_to(AD))
            role = "attacker" if f.name == "injection_tasks.py" else "legitimate"
            for tok in set(IBAN_RE.findall(text)):
                iss = iban_issue(tok)
                if iss:
                    k = (suite, "iban", tok, iss); findings[k]["files"].add(rel); findings[k]["roles"].add(role)
            for em in set(EMAIL_RE.findall(text)):
                dom = em.split("@", 1)[1].rstrip(".")
                bad = None
                if "." not in dom: bad = "email_no_tld"
                elif "_" in dom: bad = "email_domain_underscore"
                elif em.count("@") != 1 or ".." in em: bad = "email_syntax"
                if bad:
                    k = (suite, "email", em, bad); findings[k]["files"].add(rel); findings[k]["roles"].add(role)
            for host in set(URL_RE.findall(text)):
                if "_" in host:
                    k = (suite, "url", host, "hostname_underscore_invalid_dns"); findings[k]["files"].add(rel); findings[k]["roles"].add(role)
            for y, m, d in set(DATE_RE.findall(text)):
                try: datetime.date(int(y), int(m), int(d))
                except ValueError:
                    k = (suite, "date", f"{y}-{m}-{d}", "impossible_date"); findings[k]["files"].add(rel); findings[k]["roles"].add(role)
            # bill-like texts: judge the text chunk around each amount statement
            for mt in AMOUNT_TXT_RE.finditer(text.replace("\\n", "\n")):
                window = text.replace("\\n", "\n")[max(0, mt.start() - 200): mt.end() + 40]
                if not CURRENCY_RE.search(window):
                    k = (suite, "currency", mt.group(0)[:80].strip(), "amount_without_currency")
                    findings[k]["files"].add(rel); findings[k]["roles"].add(role)
    rows = []
    for (suite, kind, value, issue), v in sorted(findings.items()):
        roles = v["roles"]
        rows.append({"suite": suite, "kind": kind, "value": value, "issue": issue,
                     "role": "both" if len(roles) > 1 else next(iter(roles)), "files": sorted(v["files"])})
    summary = collections.Counter((r["suite"], r["kind"], r["issue"]) for r in rows)
    OUT.write_text(json.dumps({"agentdyn_dir": str(AD.relative_to(ROOT)), "findings": rows,
                               "summary": {f"{s}/{k}/{i}": n for (s, k, i), n in sorted(summary.items())}}, indent=1) + "\n")
    for (s, k, i), n in sorted(summary.items()): print(f"{s:10s} {k:9s} {i:34s} {n}")
    print(f"{len(rows)} findings -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
