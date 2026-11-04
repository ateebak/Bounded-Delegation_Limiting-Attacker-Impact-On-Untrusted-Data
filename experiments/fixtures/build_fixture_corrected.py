"""Build the `fixture_corrected` benchmark variant (D-015).

Copies the pinned AgentDyn checkout to external/AgentDyn-fc and applies a deterministic mapping to
every suite's data and task files:
  - every invalid IBAN from fixture_audit.json (legitimate and attacker alike: validity-matched)
    -> a fictional, checksum-valid IBAN of the correct registry length. The country is kept when it's an
    IBAN country, otherwise mapped (UK/US/CA->GB, DH->DK, CS->CZ, AC->IE, EH->ES, CF->FR);
  - hostnames/email domains containing '_' (invalid in DNS) -> '-' (e.g. www.cs_property.com -> www.cs-property.com);
  - the banking bill, which states no currency, gets a 'Currency: GBP' line (the banking suite's
    expected answers are in pounds).
Replacements are whole-token (not substring): e.g. the pseudo-IBAN DE8937040044 is replaced, but the valid
DE89370400440532013000 that begins with the same characters is untouched.
Outputs (in experiments/fixtures/): fixture_corrected_mapping.json, fixture_corrected.diff.
Validation (run separately): check_fixture_corrected.py.

`--tree rope` applies the same mapping to ROPE (external/ROPE -> external/ROPE-fc): its AutoDojo copy of
the suites AND its cached router scopes (src/rope/scopes/**), because scopes are keyed by prompt text.
Without remapping them, corrected prompts would miss the cache and ROPE would block all state-changing
tools, unfairly. The mapping is the union of the AgentDyn and ROPE audits; replacements are
hash-deterministic, so a value shared by both trees maps identically.
"""
import sys
import hashlib, json, pathlib, re, shutil, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
TREE = sys.argv[sys.argv.index("--tree") + 1] if "--tree" in sys.argv else "agentdyn"
CFG = {"agentdyn": dict(src="external/AgentDyn", dst="external/AgentDyn-fc", code="src/agentdojo", extra=[],
                        audits=["fixture_audit.json"], out="fixture_corrected"),
       "rope": dict(src="external/ROPE", dst="external/ROPE-fc", code="autodojo/src/agentdojo", extra=["src/rope/scopes"],
                    audits=["fixture_audit.json", "fixture_audit_rope.json"], out="fixture_corrected_rope")}[TREE]
SRC, DST = ROOT / CFG["src"], ROOT / CFG["dst"]
AUDIT = {"findings": [f for a in CFG["audits"] for f in json.loads((HERE / a).read_text())["findings"]]}
IBAN_LEN = {"AT": 20, "CH": 21, "CZ": 24, "DE": 22, "DK": 18, "ES": 24, "FR": 27, "GB": 22, "IE": 22, "SE": 24}
COUNTRY_MAP = {"UK": "GB", "US": "GB", "CA": "GB", "DH": "DK", "CS": "CZ", "AC": "IE", "EH": "ES", "CF": "FR"}
NOT_ACCOUNTS = {"1W@Fd"}  # audit false positive: part of a random marker string, not an email


def fictional_iban(original):
    cc = COUNTRY_MAP.get(original[:2], original[:2])
    digits = str(int(hashlib.sha256(original.encode()).hexdigest(), 16))
    n = IBAN_LEN[cc] - 4
    if cc in ("GB", "IE"):
        bban = "XFIC" + digits[: n - 4]  # fictional bank code: 4 letters + digits
    else:
        bban = digits[:n]
    check = 98 - int("".join(str(int(c, 36)) for c in bban + cc + "00")) % 97
    iban = f"{cc}{check:02d}{bban}"
    assert len(iban) == IBAN_LEN[cc] and int("".join(str(int(c, 36)) for c in iban[4:] + iban[:4])) % 97 == 1
    return iban


def build_mapping():
    m = {"iban": {}, "hostname": {}, "text_edits": []}
    for r in AUDIT["findings"]:
        if r["kind"] == "iban":
            m["iban"].setdefault(r["value"], {"new": fictional_iban(r["value"]), "role": r["role"], "issue": r["issue"]})
        elif r["kind"] in ("url", "email") and r["value"] not in NOT_ACCOUNTS and "_" in r["value"]:
            host = r["value"].split("@", 1)[-1].replace("www.", "", 1)
            m["hostname"][host] = host.replace("_", "-")
    new_ibans = [v["new"] for v in m["iban"].values()]
    assert len(set(new_ibans)) == len(new_ibans), "IBAN collision"
    m["text_edits"].append({"suite": "banking", "file": f"{CFG['code']}/data/suites/banking/injection_vectors.yaml",
                            "old": "Total\\\\t\\\\t\\\\t98.70\\\\n", "new": "Total\\\\t\\\\t\\\\t98.70\\\\nCurrency: GBP\\\\n",
                            "reason": "bill states no currency (banking expected outputs use GBP)"})
    return m


def token_sub(text, old, new):
    return re.sub(rf"(?<![A-Za-z0-9]){re.escape(old)}(?![A-Za-z0-9])", new, text)


def main():
    if DST.exists(): shutil.rmtree(DST)
    shutil.copytree(SRC, DST, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.egg-info", "runs"))
    m = build_mapping()
    targets = [p for p in (DST / CFG["code"]).rglob("*") if p.is_file() and p.suffix in (".yaml", ".py", ".txt", ".json", ".md")
               and ("/data/suites/" in str(p) or "/default_suites/" in str(p))]
    for extra in CFG["extra"]:
        targets += [p for p in (DST / extra).rglob("*.json") if p.is_file()]
    changed = set()
    for p in targets:
        t0 = t = p.read_text(errors="ignore")
        for old, v in m["iban"].items(): t = token_sub(t, old, v["new"])
        for old, new in m["hostname"].items(): t = t.replace(old, new)
        if t != t0: p.write_text(t); changed.add(str(p.relative_to(DST)))
    for e in m["text_edits"]:
        p = DST / e["file"]; t = p.read_text()
        assert t.count(e["old"]) == 1, f"text edit anchor not unique/found: {e['file']}"
        p.write_text(t.replace(e["old"], e["new"])); changed.add(e["file"])
    commit = subprocess.run(["git", "-C", str(SRC), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    m["base"] = {"repo": CFG["src"], "commit": commit, "variant": "fixture_corrected", "files_changed": sorted(changed)}
    (HERE / f"{CFG['out']}_mapping.json").write_text(json.dumps(m, indent=1) + "\n")
    diff = ""
    for sub in [CFG["code"]] + CFG["extra"]:
        diff += subprocess.run(["diff", "-ru", "--exclude=__pycache__", str(SRC / sub), str(DST / sub)],
                               capture_output=True, text=True).stdout
    (HERE / f"{CFG['out']}.diff").write_text(diff.replace(str(ROOT) + "/", ""))
    print(f"IBANs mapped: {len(m['iban'])}; hostnames mapped: {len(m['hostname'])}; text edits: {len(m['text_edits'])}; "
          f"files changed: {len(changed)}; diff lines: {diff.count(chr(10))}")


if __name__ == "__main__":
    main()
