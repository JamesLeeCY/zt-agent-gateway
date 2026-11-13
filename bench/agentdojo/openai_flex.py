"""OpenAI model for the benchmark through the Responses API, with optional Flex processing.

Why not AgentDojo's OpenAILLM: it uses /v1/chat/completions, which rejects function tools together with
reasoning for the GPT-6 models ("use /v1/responses or set reasoning_effort to 'none'"). It also sends
no `service_tier`. This element speaks the Responses API instead, statelessly (store=False, the whole
conversation is sent every turn), counts tokens, and records which tier OpenAI actually billed.

Reasoning items: each model turn's encrypted reasoning is kept and sent back before that turn's tool
calls, as OpenAI recommends for multi-step tool use, so the model keeps its chain of thought.

Flex (https://developers.openai.com/api/docs/guides/flex-processing): service_tier="flex", Batch
prices, slower. 429 "resource unavailable" is not charged: retried with exponential backoff, and after
FLEX_TRIES attempts the request goes once with the project's default tier (standard price) so a run
cannot stall forever. Every fallback is counted.
"""
import json
from collections import Counter

import openai
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, FunctionCall
from agentdojo.types import ChatAssistantMessage, get_text_content_as_str, text_content_block_from_string
from openai._types import NOT_GIVEN
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_random_exponential

FLEX_TRIES = 6


class FlexOpenAILLM(BasePipelineElement):
    def __init__(self, client: openai.OpenAI, model: str, flex: bool = False, reasoning_effort: str | None = None):
        self.client, self.model, self.flex, self.reasoning_effort = client, model, flex, reasoning_effort
        self.usage = Counter()  # read and reset by run.py after every task pair
        self.reasoning: dict[str, list] = {}  # first tool-call id of a turn -> that turn's reasoning items

    @retry(wait=wait_random_exponential(multiplier=2, max=120), stop=stop_after_attempt(FLEX_TRIES),
           retry=retry_if_exception_type((openai.RateLimitError, openai.APITimeoutError,
                                          openai.APIConnectionError, openai.InternalServerError)),
           reraise=True)
    def _create(self, tier, **kw):
        return self.client.responses.create(service_tier=tier, **kw)

    def _to_input(self, messages) -> tuple[str | None, list]:
        instructions, items = None, []
        for m in messages:
            text = get_text_content_as_str(m["content"]) if m.get("content") else ""
            if m["role"] == "system":
                instructions = text
            elif m["role"] == "user":
                items.append({"role": "user", "content": text})
            elif m["role"] == "assistant":
                calls = m.get("tool_calls") or []
                if calls:
                    items += self.reasoning.get(calls[0].id, [])
                if text:
                    items.append({"role": "assistant", "content": text})
                items += [{"type": "function_call", "call_id": c.id, "name": c.function,
                           "arguments": json.dumps(dict(c.args))} for c in calls]
            elif m["role"] == "tool":
                items.append({"type": "function_call_output", "call_id": m["tool_call_id"],
                              "output": m.get("error") or text})
        return instructions, items

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):
        instructions, items = self._to_input(messages)
        tools = [{"type": "function", "name": f.name, "description": f.description,
                  "parameters": f.parameters.model_json_schema(), "strict": False}
                 for f in runtime.functions.values()]
        kw = dict(model=self.model, instructions=instructions or NOT_GIVEN, input=items, tools=tools or NOT_GIVEN,
                  store=False, include=["reasoning.encrypted_content"],
                  reasoning={"effort": self.reasoning_effort} if self.reasoning_effort else NOT_GIVEN)
        if self.flex:
            try:
                resp = self._create("flex", **kw)
            except openai.RateLimitError as exc:
                if "quota" in str(exc).lower():  # out of credit: falling back would fail the same way
                    raise
                self.usage["flex_fallbacks"] += 1
                resp = self._create.retry_with(stop=stop_after_attempt(3))(self, NOT_GIVEN, **kw)
        else:
            resp = self._create(NOT_GIVEN, **kw)

        u = resp.usage
        if u:
            self.usage.update(
                input=u.input_tokens, output=u.output_tokens, calls=1,
                cached_input=(u.input_tokens_details.cached_tokens or 0) if u.input_tokens_details else 0,
                reasoning=(u.output_tokens_details.reasoning_tokens or 0) if u.output_tokens_details else 0)
        self.usage[f"tier_{resp.service_tier or 'unknown'}"] += 1

        calls, reasoning = [], []
        for item in resp.output:
            if item.type == "function_call":
                calls.append(FunctionCall(function=item.name, args=json.loads(item.arguments or "{}"),
                                          id=item.call_id))
            elif item.type == "reasoning":
                reasoning.append(item.model_dump(exclude_none=True))
        if calls and reasoning:
            self.reasoning[calls[0].id] = reasoning
        text = resp.output_text
        out = ChatAssistantMessage(role="assistant",
                                   content=[text_content_block_from_string(text)] if text else None,
                                   tool_calls=calls or None)
        return query, runtime, env, [*messages, out], extra_args
