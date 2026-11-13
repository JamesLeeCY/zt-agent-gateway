"""The zero-trust gateway as an AgentDojo pipeline element.

It replaces AgentDojo's ToolsExecutor: before each tool call runs, the call and the session's data-flow
context go to OPA (policy/workspace.rego for the workspace suite, policy/gateway.rego with the
suite's mapping in policy/suite_<name>.rego for banking, slack and travel). The context is rebuilt from the message history every time,
so nothing leaks between tasks:

  tainted       a tool that returns content written by other people has run (SOURCES below)
  pii_accessed  a tool that returns the user's private data has run
  call_count    tool calls so far in this task
  user_named_recipients  e-mail addresses written in the user's own request; tool output cannot add to
                it, so an injected address is never on this list
  user_request  the request itself, lower case (gateway.rego only: account numbers, names, web sites
                and values the user wrote count as named)

deny -> the call is not executed; the model gets an error message instead.
require_approval -> there is no human in a benchmark, so `approval` decides: "reject" (strict: every
approval request is refused) or "approve" (a rubber-stamping reviewer: only deny rules protect).
Any PDP failure is a deny (fail closed).
"""
import json
import re
import time
from ast import literal_eval
from pathlib import Path

import httpx
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

UNTRUSTED_SOURCES = {
    "get_unread_emails", "get_sent_emails", "get_received_emails", "get_draft_emails", "search_emails",
    "search_calendar_events", "get_day_calendar_events",
    "search_files_by_filename", "get_file_by_id", "list_files", "search_files",
}
PII_SOURCES = UNTRUSTED_SOURCES | {"search_contacts_by_name", "search_contacts_by_email"}
# suite -> (tools returning content other people wrote, tools returning the user's private data).
# Checked against AgentDojo's injection points: every tool that can return an injection is untrusted.
SOURCES = {
    "workspace": (UNTRUSTED_SOURCES, PII_SOURCES),
    # files and incoming transfers (anyone can send money with any subject)
    "banking": ({"read_file", "get_most_recent_transactions"},
                {"read_file", "get_most_recent_transactions", "get_scheduled_transactions", "get_iban",
                 "get_balance", "get_user_info"}),
    # channel names and messages are written by other members; web pages by anyone
    "slack": ({"get_channels", "read_channel_messages", "read_inbox", "get_webpage"},
              {"read_channel_messages", "read_inbox"}),
    # reviews are written by the public; calendar events by whoever invited the user
    "travel": ({"get_rating_reviews_for_hotels", "get_rating_reviews_for_restaurants",
                "get_rating_reviews_for_car_rental", "search_calendar_events", "get_day_calendar_events"},
               {"get_user_information", "search_calendar_events", "get_day_calendar_events"}),
}
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def named_recipients(user_request: str) -> list[str]:
    return sorted({m.lower() for m in EMAIL.findall(user_request)})


def initial_context(user_request: str) -> dict:
    return {"tainted": False, "pii_accessed": False, "call_count": 0,
            "user_named_recipients": named_recipients(user_request), "user_request": user_request.lower()}


class GatewayToolsExecutor(ToolsExecutor):
    def __init__(self, opa_url: str, approval: str = "reject", log_path: Path | None = None,
                 suite: str = "workspace", **kw):
        super().__init__(**kw)
        self.suite = suite
        self.untrusted, self.pii = SOURCES[suite]
        pkg = "workspace" if suite == "workspace" else "gateway"
        self.url = f"{opa_url.rstrip('/')}/v1/data/agentdojo/{pkg}"
        self.approval = approval
        self.log_path = log_path
        self.task = None  # (user task, injection task), set by the runner for the decision log
        self.http = httpx.Client(timeout=5)

    def decide(self, tool: str, args: dict, ctx: dict) -> dict:
        try:
            doc = self.http.post(self.url, json={"input": {"suite": self.suite, "action": {"tool": tool, "args": args},
                                                           "context": ctx}}).raise_for_status().json()["result"]
            d = doc["decision"]
            if d["result"] not in {"allow", "deny", "require_approval"}:
                raise ValueError(d)
            return {"result": d["result"], "reasons": sorted(d["reasons"]),
                    "recipient_class": doc.get("recipient_class"), "recipients": sorted(r[-1] if isinstance(r, list) else r for r in doc.get("recipients", []))}
        except Exception as exc:  # noqa: BLE001 - fail closed
            return {"result": "deny", "reasons": [f"R1: no decision from PDP, fail closed ({type(exc).__name__})"]}

    def query(self, query, runtime, env, messages=(), extra_args={}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        done = [m for m in messages if m["role"] == "tool"]
        executed = [m["tool_call"].function for m in done if m.get("error") is None]
        ctx = {**initial_context(query), "tainted": any(t in self.untrusted for t in executed),
               "pii_accessed": any(t in self.pii for t in executed), "call_count": len(done)}
        results = []
        for call in messages[-1]["tool_calls"]:
            for k, v in call.args.items():
                if isinstance(v, str) and is_string_list(v):
                    call.args[k] = literal_eval(v)
            ctx["call_count"] += 1
            d = self.decide(call.function, dict(call.args), ctx)
            allowed = d["result"] == "allow" or (d["result"] == "require_approval" and self.approval == "approve")
            self._log(call.function, ctx, d, allowed)
            if not allowed:
                status = "deny" if d["result"] == "deny" else "approval rejected"
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")], tool_call_id=call.id,
                    tool_call=call, error=f"BLOCKED by security gateway ({status}): {'; '.join(d['reasons'])}. "
                          "Do not retry this call. Tell the user it was not carried out and why."))
                continue
            # Run it through the normal executor (validation, formatting) as a one-call message.
            single = {**messages[-1], "tool_calls": [call]}
            _, _, env, out, _ = super().query(query, runtime, env, [*messages, single], extra_args)
            res = out[-1]
            results.append(res)
            if res.get("error") is None:
                ctx["tainted"] |= call.function in self.untrusted
                ctx["pii_accessed"] |= call.function in self.pii
        return query, runtime, env, [*messages, *results], extra_args

    def _log(self, tool, ctx, d, allowed):
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.time(), "task": self.task, "tool": tool,
                                    **{k: v for k, v in ctx.items() if k not in ("user_named_recipients", "user_request")}, **d, "executed": allowed}) + "\n")
