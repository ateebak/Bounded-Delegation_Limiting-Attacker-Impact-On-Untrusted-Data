"""Model-based envelope compiler: proposer backends + a response cache (spec §4, compiler `llm`).

The proposer sees only the trusted request and the sensitive-field table (defense/bounded/envelope.py:_llm_fields);
the deterministic validator lives there too. Raw responses are cached in experiments/envelopes/llm_<model>.json keyed by
a hash of (system, user), so every condition and repeat of a task uses the SAME compiled envelope (the compiler is not
a source of within-cell variance), and compiler accuracy can be scored against gold offline (compiler_accuracy.py).

  --compiler-model anthropic:claude-sonnet-5-5   (default; ledger-guarded, ~1 call per task)
  --compiler-model nim:<model>                   (free tier)
"""
import hashlib, json, pathlib, re

import ledger

ROOT = pathlib.Path(__file__).resolve().parents[2]


def env_key(name):
    for line in open(ROOT / ".env"):
        m = re.match(rf'\s*(?:export\s+)?{name}\s*=\s*"?([^"\n]+)"?', line)
        if m: return m.group(1).strip()
    raise SystemExit(f"{name} not in .env")


def _backend(spec, ctx):
    prov, _, model = spec.partition(":")
    if prov == "anthropic":
        import anthropic
        client = anthropic.Anthropic(api_key=env_key("ANTHROPIC_API_KEY"), max_retries=1)

        def complete(system, user):
            ledger.guard("anthropic", model)
            msg = client.messages.create(model=model, max_tokens=4000, system=system, messages=[{"role": "user", "content": user}])
            ledger.record(ctx["ledger_id"], "anthropic", "api", model, msg.usage.input_tokens, 0, msg.usage.output_tokens)
            return "".join(b.text for b in msg.content if b.type == "text")
        return complete
    if prov == "nim":
        import openai
        client = openai.OpenAI(api_key=env_key("NVIDIA_API_KEY"), base_url="https://integrate.api.nvidia.com/v1", max_retries=2, timeout=300)

        def complete(system, user):
            from retry import with_retry  # D-042
            r = with_retry(client.chat.completions.create, model=model, temperature=0, max_tokens=2000, label=f"compiler:{model}",
                                               messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            ledger.record(ctx["ledger_id"], "nim", "api", model, r.usage.prompt_tokens, 0, r.usage.completion_tokens)
            return r.choices[0].message.content or ""
        return complete
    raise SystemExit(f"unknown compiler backend {spec}")


def cached_complete(spec, ctx):
    path = ROOT / "experiments/envelopes" / f"llm_{spec.replace(':', '_').replace('/', '_')}.json"
    cache = json.loads(path.read_text()) if path.exists() else {}
    live = None

    def complete(system, user):
        nonlocal live
        h = hashlib.sha256((system + "\0" + user).encode()).hexdigest()[:16]
        if h not in cache:
            live = live or _backend(spec, ctx)
            cache[h] = {"user": user, "raw": live(system, user)}
            path.write_text(json.dumps(cache, indent=1) + "\n")
        return cache[h]["raw"]
    return complete
