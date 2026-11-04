"""Baseline defenses for the runner, built from the original authors' code (MIT).

ROPE  (external/ROPE[-fc]/src/rope): audited floor + cached `opus` router scopes, as in the paper's main condition.
      Prompts absent from the cache (our extension tasks) use ROPE's LIVE router code (rope.router.route_and_scope)
      with claude-sonnet-5-5 reading only the trusted request -- DEVIATION, recorded per episode as
      `rope_router = live:claude-sonnet-5-5`. Suites without an audited floor (workspace) are NOT RUN for ROPE (n/a).
Progent (ROPE's AutoDojo port of the released secagent code): policy generation + LLM updates, policy model gpt-4o
      (the paper's default). The released code (official repo @5be7b63, 2026-09-24, and this port) contains NO v3
      SMT narrowing/expansion check or approver modes (finding F-11); this baseline is "Progent (released code)".
      Policy-LLM calls are budget-guarded and recorded with ESTIMATED tokens (chars/4; api_request returns text only).
"""
import os, re, sys

import ledger

ROOT_DEFAULT = None


def env_key(root, name):
    for line in open(root / ".env"):
        m = re.match(rf'\s*(?:export\s+)?{name}\s*=\s*"?([^"\n]+)"?', line)
        if m: return m.group(1).strip()
    raise SystemExit(f"{name} not in .env")


def _anthropic_complete(root, ctx, model="claude-sonnet-5-5"):
    import anthropic
    client = anthropic.Anthropic(api_key=env_key(root, "ANTHROPIC_API_KEY"), max_retries=1)

    def complete(system, user):
        ledger.guard("anthropic", model)
        msg = client.messages.create(model=model, max_tokens=4000, system=system, messages=[{"role": "user", "content": user}])
        u = msg.usage
        ledger.record(ctx["ledger_id"], "anthropic", "api", model, u.input_tokens, 0, u.output_tokens)
        return "".join(b.text for b in msg.content if b.type == "text")
    return complete


def build_rope(llm, suite, prompt, ctx, root, rope_src):
    sys.path.insert(0, str(rope_src))
    from rope import pipeline as rp
    from rope.scopes_io import load_floor, load_router_scopes
    try:
        floor = load_floor(suite)
    except FileNotFoundError:
        return None, "n/a: no audited floor for suite"
    try:
        _, scopes = load_router_scopes("opus", suite)
    except FileNotFoundError:
        scopes = {}
    if prompt in scopes:
        return rp.build_routed_pipeline(llm, suite_name=suite, floor=floor, cached_scopes=scopes), "cached:opus"
    return (rp.build_routed_pipeline(llm, suite_name=suite, floor=floor, live_router_complete=_anthropic_complete(root, ctx)),
            "live:claude-sonnet-5-5")


POLICY_FAILURES = []  # D-040: Progent policy-model calls that failed after retries (cleared per episode by the runner)


def build_progent(llm, suite, ctx, root, policy_model="gpt-4o", approver=None):
    os.environ["SECAGENT_POLICY_MODEL"] = policy_model
    os.environ["SECAGENT_GENERATE"] = "True"
    os.environ["SECAGENT_UPDATE"] = "True"
    os.environ.setdefault("SECAGENT_IGNORE_UPDATE_ERROR", "True")
    os.environ["SECAGENT_BASE_URL"] = "https://api.openai.com/v1"
    os.environ["SECAGENT_API_KEY"] = env_key(root, "OPENAI_API_KEY")
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str
    from agentdojo.agent_pipeline.progent_defense import ProgentConfig, ProgentPolicyInit, ProgentToolsExecutor
    from agentdojo.agent_pipeline.progent_defense.secagent import tool as st
    if not getattr(st.api_request, "_ledger_wrapped", False):
        orig = st.api_request

        def api_request(sys_prompt, user_prompt, temperature=0.0):
            # D-040: retry rate limits with exponential backoff. SECAGENT_IGNORE_UPDATE_ERROR would otherwise skip a
            # rate-limited policy update SILENTLY (stage 1b: 27-35 429s per lane with 6 parallel gpt-4o lanes).
            # A call that still fails is counted in POLICY_FAILURES (recorded per episode) and re-raised.
            import time as _t
            for attempt in range(8):
                ledger.guard("openai", policy_model)
                try:
                    out = orig(sys_prompt, user_prompt, temperature)
                    break
                except Exception as e:
                    if "429" in str(e) or "RateLimit" in type(e).__name__:
                        _t.sleep(min(120, 5 * 2 ** attempt)); continue
                    POLICY_FAILURES.append(f"{type(e).__name__}: {str(e)[:120]}"); raise
            else:
                POLICY_FAILURES.append("rate limit after 8 retries"); raise RuntimeError("policy model rate-limited")
            ledger.record(ctx["ledger_id"], "openai", "api", policy_model, (len(sys_prompt) + len(user_prompt)) // 4, 0,
                          len(str(out or "")) // 4)
            return out
        api_request._ledger_wrapped = True
        st.api_request = api_request
    note = f"progent-released:{policy_model}"
    if approver is not None:  # D-038: our reimplementation of the v3 approver around the released updater
        import progent_approver
        progent_approver.install(approver)
        note = f"progent-released:{policy_model}+approver-reimpl:{approver.mode}" + (f":{approver.sim}" if approver.mode == "manual" else "")
    cfg = ProgentConfig(policy_model=policy_model, generate=True, update=True, cache_dir=None, suite=suite)
    loop = ToolsExecutionLoop([ProgentToolsExecutor(tool_result_to_str, update=True), llm])
    return AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), ProgentPolicyInit(cfg), llm, loop]), note


# ── DRIFT (li2025drift) via ROPE's AutoDojo port (agent_pipeline/drift_defense) ────────────────────────────────────
# The port routes models to a local vLLM or OpenRouter; we build its OpenAI-compatible client directly instead:
# the agent on the run's own endpoint (NIM or OpenAI), the defense machinery on gpt-4o-mini (the DRIFT paper's
# constraint model, §3), no Tier-1 cache (constraints computed live per episode). Every call is ledger-recorded and
# OpenAI calls are budget-guarded. Anthropic agents: n/a (the DRIFT client is OpenAI-format only).
DRIFT_DEFENSE_MODEL = "gpt-4o-mini"  # the DRIFT paper used gpt-4o-mini; the alias matches our free allotment


def _ledgered_drift_client(prov, model, root, ctx):
    from agentdojo.agent_pipeline.drift_defense.drift_client import OpenAIModel
    if prov == "nim":
        c = OpenAIModel(model=model, api_key=env_key(root, "NVIDIA_API_KEY"), api_base="https://integrate.api.nvidia.com/v1")
    else:
        c = OpenAIModel(model=model, api_key=env_key(root, "OPENAI_API_KEY"), api_base="https://api.openai.com/v1")
    acc = c._account

    def account(usage, name, _acc=acc):
        _acc(usage, name)
        if usage is not None:
            ledger.record(ctx["ledger_id"], prov, "api", model, usage.prompt_tokens, 0, usage.completion_tokens)
    c._account = account
    for meth in ("agent_run", "llm_run"):
        orig = getattr(c, meth)

        def guarded(*a, _orig=orig, **k):
            from retry import with_retry  # D-042: DRIFT's client doesn't retry 429/5xx
            if prov == "openai": ledger.guard("openai", model)
            return with_retry(_orig, *a, label=f"drift:{prov}:{model}", **k)
        setattr(c, meth, guarded)
    return c


_NATIVE_CALL = re.compile(r"<\|tool_call>\s*call:(\w+)\s*(\{.*?\})\s*<tool_call\|>", re.S)


def gemma_native_to_drift(text):
    """Compatibility shim (D-037 deviation): some models (gemma on NIM) answer DRIFT's text-format tool-calling
    prompt with their NATIVE syntax `<|tool_call>call:fn{k:<|"|>v<|"|>,n:1}<tool_call|>`; DRIFT's parser only reads
    `<function_call>[fn(k="v", n=1)]</function_call>`, so the call was silently dropped. Rewrite native calls into
    DRIFT's format; text without native calls is returned unchanged."""
    if not text or "<|tool_call>" not in text:
        return text
    calls = []
    for name, body in _NATIVE_CALL.findall(text):
        b = body.replace('<|"|>', '"')[1:-1]
        b = re.sub(r'(^|,)\s*(\w+)\s*:', lambda m: f"{m.group(1)} {m.group(2)}=", b)
        calls.append(f"{name}({b.strip()})")
    if not calls:
        return text
    return _NATIVE_CALL.sub("", text) + f"\n<function_call>[{', '.join(calls)}]</function_call>"


_MINIMAX_TOKEN = "]<]minimax[>["
_DRIFT_CALL = re.compile(r"<function_call>\s*\[(.*?)\]\s*</function_call>", re.S)
_JSON_CALL = re.compile(r'\{\s*"name"\s*:\s*"\w+"')
_INVOKE = re.compile(r'<invoke name="(\w+)">(.*?)</invoke>', re.S)
_CALL_LIST = re.compile(r"\[\s*(\w+\(.*?\)(?:\s*,\s*\w+\(.*?\))*)\s*\]", re.S)
_PARAM = re.compile(r'<parameter name="(\w+)">(.*?)</parameter>|<(\w+)>(.*?)</\3>', re.S)


def _literal(v):
    import json
    try:
        return repr(json.loads(v))
    except Exception:
        return repr(v.strip())


def minimax_native_to_drift(text):
    """Compatibility shim (D-037 deviation, extended D-049): minimax-m3.1-flash often answers DRIFT's text-format
    tool-calling prompt with its NATIVE syntax -- JSON `<tool_call>{"name": fn, "arguments": {...}}</tool_call>` or
    XML `<invoke name="fn"><parameter name="k">v</parameter></invoke>` (or `<k>v</k>`), interleaved with the stray
    token `]<]minimax[>[` -- and DRIFT's parser silently dropped those calls (stage 10 run 20261030T101842Z-5195df).
    Strip the token; if no non-empty DRIFT-format call is present, rewrite the native calls (or a DRIFT list whose
    opening tag was garbled) into `<function_call>[fn(k=v)]</function_call>`. Other text is returned unchanged."""
    if not text:
        return text
    text = text.replace(_MINIMAX_TOKEN, "")
    if any(m.strip() for m in _DRIFT_CALL.findall(text)):
        return text
    import json
    calls = []
    dec = json.JSONDecoder()
    for m in _JSON_CALL.finditer(text):
        try:
            obj = dec.raw_decode(text, m.start())[0]
            calls.append(f"{obj['name']}({', '.join(f'{k}={v!r}' for k, v in (obj.get('arguments') or {}).items())})")
        except Exception:
            pass
    for name, body in _INVOKE.findall(text):
        ps = [(m[0] or m[2], m[1] if m[0] else m[3]) for m in _PARAM.findall(body)]
        calls.append(f"{name}({', '.join(f'{k}={_literal(v)}' for k, v in ps)})")
    if not calls:  # DRIFT-format call lists under a native/garbled tag, e.g. <tool_call>[fn(k="v")]</tool_call>
        import ast
        rest = re.sub(r"<(function_thought|final_answer)>.*?</\1>", "", text, flags=re.S)
        for m in _CALL_LIST.finditer(rest):
            body = re.sub(r"\bnull\b", "None", re.sub(r"\btrue\b", "True", re.sub(r"\bfalse\b", "False", m.group(1))))
            try:
                if all(isinstance(e, ast.Call) for e in ast.parse(f"[{body}]", mode="eval").body.elts): calls.append(body.strip())
            except SyntaxError:
                pass
    if not calls:
        return text
    # DRIFT reads only the FIRST <function_call> block: drop empty/garbled ones before appending the translation.
    text = re.sub(r"<function_call>.*?</function_call>", "", text, flags=re.S).replace("</function_call>", "")
    return text + f"\n<function_call>[{', '.join(calls)}]</function_call>"


def native_to_drift(text):
    return minimax_native_to_drift(gemma_native_to_drift(text))


def build_drift(model_spec, ctx, root):
    prov, model = model_spec.split(":", 1)
    if prov not in ("nim", "openai"):
        return None, "n/a: DRIFT client is OpenAI-format only"
    if model.startswith(("gpt-5.6", "gpt-6")):
        return None, "n/a: model needs the Responses API; DRIFT client uses Chat Completions"
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.basic_elements import InitQuery
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.agent_pipeline.drift_defense import DRIFTLLM, DRIFTToolsExecutionLoop, DriftConfig
    agent = _ledgered_drift_client(prov, model, root, ctx)
    _run = agent.agent_run
    agent.agent_run = lambda *aa, _r=_run, **kk: [native_to_drift(x) for x in _r(*aa, **kk)]
    defense = _ledgered_drift_client("openai", DRIFT_DEFENSE_MODEL, root, ctx)
    drift_llm = DRIFTLLM(agent, defense, config=DriftConfig(adaptive_attack=False), cache=None)
    return AgentPipeline([InitQuery(), drift_llm, DRIFTToolsExecutionLoop([ToolsExecutor(), drift_llm])]), \
        f"drift-port:defense={DRIFT_DEFENSE_MODEL},no-cache,native-call-shim"


# ── CaMeL (debenedetti2025camel) via ROPE's AutoDojo port (defenses/camel, vendored upstream code) ─────────────────
# Paper configuration: the suite's security-policy engine enforced live (`camel`, not `camel_nopolicy`). Policy
# engines: upstream for the AgentDojo suites; the AgentDyn ones were written by the ROPE authors (seeded from ROPE's
# audited floor) -- recorded per episode. We build the pipeline ourselves (same elements as make_tools_pipeline's
# live branch) so that the privileged LLM is the run's ledger-instrumented LLM and the quarantined LLM is a
# pydantic-ai model on the same endpoint and model, with no global env changes.
_CAMEL_AGENTDYN = {"github", "shopping", "dailylife"}


def _patch_pydantic_ai_ledger(prov, model, ctx):
    import pydantic_ai
    if getattr(pydantic_ai.Agent.run_sync, "_ledger_wrapped", False): return
    orig = pydantic_ai.Agent.run_sync

    def run_sync(self, *a, **k):
        if prov in ("openai", "anthropic"): ledger.guard(prov, model)
        from retry import with_retry  # D-042: quarantined-LLM calls
        r = with_retry(orig, self, *a, label=f"camel-q:{prov}:{model}", **k)
        try:
            u = r.usage()
            ledger.record(ctx["ledger_id"], prov, "api", model, getattr(u, "input_tokens", None) or getattr(u, "request_tokens", 0) or 0,
                          0, getattr(u, "output_tokens", None) or getattr(u, "response_tokens", 0) or 0)
        except Exception:
            pass
        return r
    run_sync._ledger_wrapped = True
    pydantic_ai.Agent.run_sync = run_sync


def build_camel(llm, model_spec, suite, ctx, root):
    prov, model = model_spec.split(":", 1)
    from agentdojo.agent_pipeline import agent_pipeline as ap
    if suite not in ap.CAMEL_SUPPORTED_SUITES:
        return None, f"n/a: no CaMeL policy engine for {suite}"
    ap._add_camel_to_syspath()
    import agentdojo.task_suite.load_suites  # noqa: F401  (CaMeL's circular import; see agent_pipeline._build_camel_pipeline)
    from camel.models import _SECURITY_POLICY_ENGINES
    from camel.pipeline_elements.privileged_llm import PrivilegedLLM
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.basic_elements import InitQuery
    if prov == "nim":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider
        q = OpenAIChatModel(model, provider=OpenAIProvider(base_url="https://integrate.api.nvidia.com/v1", api_key=env_key(root, "NVIDIA_API_KEY")))
    elif prov == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel
        from pydantic_ai.providers.openai import OpenAIProvider
        prov_o = OpenAIProvider(api_key=env_key(root, "OPENAI_API_KEY"))
        # gpt-5.6/6.x reject tools on Chat Completions (D-024); pydantic-ai's structured output uses tools, so the
        # quarantined LLM goes through the Responses API for those models (D-038). Other models: Chat Completions.
        q = (OpenAIResponsesModel(model, provider=prov_o) if model.startswith(("gpt-5.6", "gpt-6"))
             else OpenAIChatModel(model, provider=prov_o))
    else:
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider
        q = AnthropicModel(model, provider=AnthropicProvider(api_key=env_key(root, "ANTHROPIC_API_KEY")))
    _patch_pydantic_ai_ledger(prov, model, ctx)
    p = PrivilegedLLM(llm, _SECURITY_POLICY_ENGINES[suite], f"openai:{model}")
    p.quarantined_llm_model = q  # replaces the string set by the constructor (it only special-cases o1 -> gpt-4o)
    policy_src = "rope-authored" if suite in _CAMEL_AGENTDYN else "upstream"
    return AgentPipeline([InitQuery(), p]), f"camel-port:live-policies({policy_src}),q-llm=same-model"
