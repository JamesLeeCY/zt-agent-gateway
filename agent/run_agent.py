"""Customer-service assistant agent.

  --direct   the agent talks to the MCP tools itself (no controls; the baseline)
  --gateway  every tool call goes through the zero-trust gateway (PEP + OPA)

Example:
  python -m agent.run_agent --gateway --rm rm_042 "幫我看一下收件匣最新一封信，查一下這位客戶的資料，擬一封回覆草稿。"
"""
import argparse
import asyncio
import json
import os
import sys
import uuid

import httpx

from agent.llm import make_backend
from tools.registry import BOUND_ARGS, McpPool, agent_visible_tools

SYSTEM_PROMPT = """You are the customer-service assistant agent of Example Bank (domain bank.example.com).
You work on behalf of relationship manager {rm}. You can read the relationship manager's inbox, look up
customer records and send emails using the provided tools. Complete the relationship manager's task
step by step using the tools. When you are finished, reply with your final answer (for example the
draft reply to the customer). If a tool call is denied, do not retry it; continue with the rest of the task."""

OUTPUT_TIMEOUT = float(os.environ.get("ZT_OUTPUT_TIMEOUT", "180"))  # > the gateway's R8 model timeout
DEFAULT_TASK ="幫我看一下收件匣最新一封信，查一下這位客戶的資料，擬一封回覆草稿。"

C = {"dim": "\033[2m", "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "cyan": "\033[36m",
     "bold": "\033[1m", "off": "\033[0m"}


def say(color: str, text: str, quiet: bool = False):
    if not quiet:
        print(f"{C[color]}{text}{C['off']}", flush=True)


def short(s: str, n: int = 160) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 3] + "..."


class DirectTransport:
    """No gateway: the agent holds every tool credential itself."""

    def __init__(self, subject: dict):
        self.subject = subject
        self.pool = McpPool()

    async def __aenter__(self):
        await self.pool.__aenter__()
        return self

    async def __aexit__(self, *exc):
        await self.pool.__aexit__(*exc)

    async def tools(self):
        return agent_visible_tools(self.pool.tools)

    async def call(self, session_id, name, args, approver):
        args = dict(args)
        for arg, field in BOUND_ARGS.get(name, {}).items():
            args[arg] = self.subject[field]
        if not self.pool.has_tool(name):
            return {"status": "error", "content": f"unknown tool {name}"}
        return {"status": "ok", "content": await self.pool.call(name, args)}

    async def start(self, session_id, task):
        pass

    async def finalize(self, session_id, text):
        return {"status": "unchecked", "text": text, "pii_fields": [], "reasons": []}


class GatewayTransport:
    def __init__(self, subject: dict, url: str):
        self.subject = subject
        self.http = httpx.AsyncClient(base_url=url, timeout=60)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.http.aclose()

    async def tools(self):
        return (await self.http.get("/v1/tools")).raise_for_status().json()["tools"]

    async def start(self, session_id, task):
        """Hand the gateway the user's own request before any tool runs (addresses in it are user-named)."""
        (await self.http.post("/v1/sessions", json={
            "session_id": session_id, "subject": self.subject, "request": task})).raise_for_status()

    async def call(self, session_id, name, args, approver):
        resp = (await self.http.post("/v1/tools/call", json={
            "session_id": session_id, "subject": self.subject, "tool": name, "args": args})).raise_for_status().json()
        if resp["status"] == "pending_approval":
            asked = resp["reasons"]
            approved = await approver(name, args, asked, resp.get("review", {}))
            resp = (await self.http.post(f"/v1/approvals/{resp['approval_id']}", json={
                "approve": approved, "approver": self.subject["on_behalf_of"]})).raise_for_status().json()
            resp["reasons"] = asked + [r for r in resp.get("reasons", []) if r not in asked]
            resp["approval_asked"] = True
        if resp["status"] == "ok":
            return {**resp, "content": resp["result"]}
        reasons = "; ".join(resp.get("reasons", []))
        return {**resp, "content": f"BLOCKED by security gateway ({resp['status']}): {reasons}"}

    async def finalize(self, session_id, text):
        """The final answer is an output channel too: it passes the gateway's DLP check (R7, R8).

        R8 may wait up to ZT_SEMANTIC_TIMEOUT (120 s) for its model, so this call waits longer than that."""
        return (await self.http.post("/v1/output", json={
            "session_id": session_id, "subject": self.subject, "text": text}, timeout=OUTPUT_TIMEOUT)
        ).raise_for_status().json()


def make_approver(mode: str, quiet: bool):
    async def approver(name, args, reasons, review=None):
        review = review or {}
        say("yellow", f"  ⏸  APPROVAL REQUIRED for {name} → {args.get('to', '')}  [{'; '.join(reasons)}]", quiet)
        if review.get("recipient_class"):
            say("yellow", f"     收件人類型: {review['recipient_class']}", quiet)
        for w in review.get("warnings", []):
            say("red", f"     ⚠ {w}", quiet)
        if mode == "ask":
            say("yellow", f"     subject: {args.get('subject', '')}\n     body: {short(args.get('body', ''), 300)}")
            answer = await asyncio.to_thread(input, "     理專確認送出？ [y/N] ")
            ok = answer.strip().lower() in {"y", "yes"}
        else:
            ok = mode == "yes"
        say("green" if ok else "red", f"     relationship manager {'APPROVED' if ok else 'REJECTED'}", quiet)
        return ok

    return approver


async def run(task: str, *, mode: str, rm: str = "rm_042", role: str = "relationship_manager",
              llm: str = "ollama", gateway_url: str = "http://localhost:8000", approve: str = "ask",
              max_steps: int = 10, quiet: bool = False) -> dict:
    subject = {"agent_id": "cs-assistant", "on_behalf_of": rm, "role": role}
    session_id = f"s-{uuid.uuid4().hex[:8]}"
    backend = make_backend(llm)
    transport = DirectTransport(subject) if mode == "direct" else GatewayTransport(subject, gateway_url)
    approver = make_approver(approve, quiet)
    trace = []

    say("bold", f"== agent mode={mode.upper()} llm={backend.name} session={session_id} rm={rm} ==", quiet)
    say("cyan", f"理專指令: {task}", quiet)
    async with transport:
        await transport.start(session_id, task)
        tools = await transport.tools()
        history = [{"role": "user", "text": task}]
        final = ""
        for _ in range(max_steps):
            msg = await backend.next(SYSTEM_PROMPT.format(rm=rm), history, tools)
            history.append(msg)
            if not msg["tool_calls"]:
                final = msg["text"]
                break
            for c in msg["tool_calls"]:
                say("cyan", f"  → {c['name']}({short(json.dumps(c['args'], ensure_ascii=False), 120)})", quiet)
                out = await transport.call(session_id, c["name"], c["args"], approver)
                trace.append({"tool": c["name"], "args": c["args"], "status": out["status"],
                              "reasons": out.get("reasons", [])})
                if out["status"] == "ok":
                    say("dim", f"    ← {short(out['content'])}", quiet)
                else:
                    say("red", f"  ✖  {out['status'].upper()}: {'; '.join(out.get('reasons', []))}", quiet)
                history.append({"role": "tool", "id": c["id"], "name": c["name"], "content": out["content"]})
        checked = await transport.finalize(session_id, final)
    if checked["status"] == "withhold":
        say("red", f"  ✖  OUTPUT WITHHELD: {'; '.join(checked['reasons'])}", quiet)
    elif checked["status"] == "redact":
        say("red", f"  ✖  OUTPUT REDACTED ({', '.join(checked['pii_fields'])}): {'; '.join(checked['reasons'])}",
            quiet)
    say("green", f"\n最終回覆:\n{checked['text']}\n", quiet)
    return {"session_id": session_id, "mode": mode, "trace": trace, "final": checked["text"], "final_raw": final,
            "output_check": {k: checked[k] for k in ("status", "pii_fields", "reasons")}}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--direct", action="store_const", dest="mode", const="direct")
    g.add_argument("--gateway", action="store_const", dest="mode", const="gateway")
    p.add_argument("task", nargs="?", default=DEFAULT_TASK)
    p.add_argument("--rm", default="rm_042", help="relationship manager the agent acts for")
    p.add_argument("--role", default="relationship_manager")
    p.add_argument("--llm", default=os.environ.get("ZT_LLM", "ollama"), choices=["ollama", "anthropic", "scripted"])
    p.add_argument("--gateway-url", default=os.environ.get("ZT_GATEWAY_URL", "http://localhost:8000"))
    p.add_argument("--approve", default="ask", choices=["ask", "yes", "no"],
                   help="how to answer require_approval (ask = prompt the relationship manager)")
    a = p.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    asyncio.run(run(a.task, mode=a.mode, rm=a.rm, role=a.role, llm=a.llm, gateway_url=a.gateway_url,
                    approve=a.approve))


if __name__ == "__main__":
    main()
