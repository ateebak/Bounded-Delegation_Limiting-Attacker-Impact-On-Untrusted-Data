"""LLM adapters for current SDKs/models that AutoDojo's built-ins don't support (Week 3 harness).

1. anthropic_request: replacement for agentdojo.agent_pipeline.llms.anthropic_llm.chat_completion_request.
   The installed anthropic SDK 1.x removed sampling parameters from messages.stream()/create() (AutoDojo targets 0.x,
   so every Claude call raised TypeError). We call messages.create without temperature/thinking overrides (model
   defaults, e.g. adaptive thinking on Sonnet 5.5), and record usage in the cost ledger behind the budget guard.
2. OpenAIResponsesLLM: an AutoDojo pipeline element on the OpenAI Responses API. gpt-5.6*/gpt-6* reject function tools
   on Chat Completions unless reasoning_effort='none', which those models also reject, so Responses is the only
   tool-calling route. Turns are chained with previous_response_id (the model's reasoning state stays server-side);
   only the new function_call_output items are sent each turn. The state resets when a new episode starts.
"""
import json

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import FunctionCall

import ledger


def make_anthropic_request(ctx):
    async def anthropic_request(client, model, messages, tools, max_tokens, system_prompt=None, temperature=None,
                                thinking_budget_tokens=None):
        ledger.guard("anthropic", model)
        kw = dict(model=model, messages=messages, max_tokens=max(int(max_tokens or 0), 16000))
        if tools: kw["tools"] = tools
        if system_prompt: kw["system"] = system_prompt
        msg = await client.messages.create(**kw)
        u = msg.usage
        cr = getattr(u, "cache_read_input_tokens", 0) or 0
        ledger.record(ctx["ledger_id"], "anthropic", "api", model, u.input_tokens + cr, cr, u.output_tokens)
        return msg
    return anthropic_request


def _text(content):
    if content is None: return ""
    if isinstance(content, str): return content
    return "".join(b.get("content", "") for b in content if isinstance(b, dict) and b.get("type", "text") == "text")


class OpenAIResponsesLLM(BasePipelineElement):
    name = "openai-responses"

    def __init__(self, client, model, ctx):
        self.client, self.model, self.ctx = client, model, ctx
        self._prev_id, self._sent, self._episode = None, 0, None

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        if self._episode != self.ctx["ledger_id"] or len(messages) < self._sent:
            self._prev_id, self._sent, self._episode = None, 0, self.ctx["ledger_id"]
        tools = [{"type": "function", "name": f.name, "description": f.description,
                  "parameters": f.parameters.model_json_schema()} for f in runtime.functions.values()]
        instructions = "\n".join(_text(m["content"]) for m in messages if m["role"] == "system")
        items = []
        for m in list(messages)[self._sent:]:
            if m["role"] == "user":
                items.append({"role": "user", "content": _text(m["content"])})
            elif m["role"] == "tool" and self._prev_id is not None:
                items.append({"type": "function_call_output", "call_id": m["tool_call"].id or "call_0",
                              "output": _text(m["content"]) or (m.get("error") or "")})
        ledger.guard("openai", self.model)
        kw = dict(model=self.model, input=items, tools=tools, tool_choice="auto", max_output_tokens=16000)
        if instructions: kw["instructions"] = instructions
        if self._prev_id: kw["previous_response_id"] = self._prev_id
        r = self.client.responses.create(**kw)
        u = r.usage
        ledger.record(self.ctx["ledger_id"], "openai", "api", self.model, u.input_tokens,
                      getattr(getattr(u, "input_tokens_details", None), "cached_tokens", 0) or 0, u.output_tokens,
                      getattr(getattr(u, "output_tokens_details", None), "reasoning_tokens", 0) or 0)
        self._prev_id = r.id
        calls = [FunctionCall(function=o.name, args=json.loads(o.arguments or "{}"), id=o.call_id)
                 for o in r.output if o.type == "function_call"]
        msg = {"role": "assistant", "content": [{"type": "text", "content": r.output_text or ""}], "tool_calls": calls or None}
        messages = [*messages, msg]
        self._sent = len(messages)
        return query, runtime, env, messages, extra_args
