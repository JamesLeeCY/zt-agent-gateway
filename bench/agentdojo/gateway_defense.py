"""The zero-trust gateway as an AgentDojo pipeline element.

It replaces AgentDojo's ToolsExecutor: before each tool call runs, the call and the session's data-flow
context go to OPA (policy/workspace.rego). The context is rebuilt from the message history every time,
so nothing leaks between tasks:

  tainted       a tool that returns content written by other people has run (mail, calendar, files)
  pii_accessed  a tool that returns the user's private data has run (the same tools plus contacts)
  call_count    tool calls so far in this task

deny -> the call is not executed; the model gets an error message instead.
require_approval -> there is no human in a benchmark, so `approval` decides: "reject" (strict: every
approval request is refused) or "approve" (a rubber-stamping reviewer: only deny rules protect).
Any PDP failure is a deny (fail closed).
"""
import json
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


class GatewayToolsExecutor(ToolsExecutor):
    def __init__(self, opa_url: str, approval: str = "reject", log_path: Path | None = None, **kw):
        super().__init__(**kw)
        self.url = f"{opa_url.rstrip('/')}/v1/data/agentdojo/workspace"
        self.approval = approval
        self.log_path = log_path
        self.task = None  # (user task, injection task), set by the runner for the decision log
        self.http = httpx.Client(timeout=5)

    def decide(self, tool: str, args: dict, ctx: dict) -> dict:
        try:
            doc = self.http.post(self.url, json={"input": {"action": {"tool": tool, "args": args},
                                                           "context": ctx}}).raise_for_status().json()["result"]
            d = doc["decision"]
            if d["result"] not in {"allow", "deny", "require_approval"}:
                raise ValueError(d)
            return {"result": d["result"], "reasons": sorted(d["reasons"]),
                    "recipient_class": doc.get("recipient_class")}
        except Exception as exc:  # noqa: BLE001 - fail closed
            return {"result": "deny", "reasons": [f"R1: no decision from PDP, fail closed ({type(exc).__name__})"]}

    def query(self, query, runtime, env, messages=(), extra_args={}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        done = [m for m in messages if m["role"] == "tool"]
        executed = [m["tool_call"].function for m in done if m.get("error") is None]
        ctx = {"tainted": any(t in UNTRUSTED_SOURCES for t in executed),
               "pii_accessed": any(t in PII_SOURCES for t in executed), "call_count": len(done)}
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
                    tool_call=call, error=f"BLOCKED by security gateway ({status}): {'; '.join(d['reasons'])}"))
                continue
            # Run it through the normal executor (validation, formatting) as a one-call message.
            single = {**messages[-1], "tool_calls": [call]}
            _, _, env, out, _ = super().query(query, runtime, env, [*messages, single], extra_args)
            res = out[-1]
            results.append(res)
            if res.get("error") is None:
                ctx["tainted"] |= call.function in UNTRUSTED_SOURCES
                ctx["pii_accessed"] |= call.function in PII_SOURCES
        return query, runtime, env, [*messages, *results], extra_args

    def _log(self, tool, ctx, d, allowed):
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.time(), "task": self.task, "tool": tool, **ctx, **d, "executed": allowed}) + "\n")
