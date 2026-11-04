"""LLM backends with tool calling, behind one small interface.

History uses a neutral format:
  {"role": "user", "text": str}
  {"role": "assistant", "text": str, "tool_calls": [{"id", "name", "args"}]}
  {"role": "tool", "id": str, "name": str, "content": str}
Each backend's `next(system, history, tools)` returns an assistant message in that format.
"""
import json
import os
import re
import uuid

import httpx


class OllamaBackend:
    def __init__(self, model: str | None = None, url: str | None = None):
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct")
        self.url = (url or os.environ.get("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.name = f"ollama/{self.model}"

    def _messages(self, system, history):
        out = [{"role": "system", "content": system}]
        for m in history:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["text"]})
            elif m["role"] == "assistant":
                calls = [{"function": {"name": c["name"], "arguments": c["args"]}} for c in m["tool_calls"]]
                out.append({"role": "assistant", "content": m["text"], "tool_calls": calls})
            else:
                out.append({"role": "tool", "content": m["content"], "tool_name": m["name"]})
        return out

    async def next(self, system, history, tools):
        payload = {
            "model": self.model,
            "messages": self._messages(system, history),
            "tools": [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                        "parameters": t["input_schema"]}} for t in tools],
            "stream": False,
            "options": {"temperature": float(os.environ.get("ZT_TEMPERATURE", "0.2"))},
        }
        async with httpx.AsyncClient(timeout=300) as client:
            for attempt in range(3):  # Ollama returns 500 when the model emits a malformed tool call
                resp = await client.post(f"{self.url}/api/chat", json=payload)
                if resp.status_code < 500:
                    break
            resp.raise_for_status()
        msg = resp.json()["message"]
        text = msg.get("content") or ""
        calls = []
        for c in msg.get("tool_calls") or []:
            args = c["function"].get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            calls.append({"id": uuid.uuid4().hex[:8], "name": c["function"]["name"], "args": args})
        if not calls:  # some local models print the call as text instead of using the tool channel
            for raw in re.findall(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", text, re.S):
                try:
                    c = json.loads(raw)
                    calls.append({"id": uuid.uuid4().hex[:8], "name": c["name"], "args": c.get("arguments", {})})
                except (json.JSONDecodeError, KeyError):
                    pass
            if calls:
                text = ""
        return {"role": "assistant", "text": text, "tool_calls": calls}


class AnthropicBackend:
    def __init__(self, model: str | None = None):
        import anthropic

        self.model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
        self.client = anthropic.AsyncAnthropic()
        self.name = f"anthropic/{self.model}"

    def _messages(self, history):
        out = []
        for m in history:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["text"]})
            elif m["role"] == "assistant":
                blocks = [{"type": "text", "text": m["text"]}] if m["text"] else []
                blocks += [{"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]}
                           for c in m["tool_calls"]]
                out.append({"role": "assistant", "content": blocks})
            else:
                block = {"type": "tool_result", "tool_use_id": m["id"], "content": m["content"]}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    async def next(self, system, history, tools):
        resp = await self.client.messages.create(
            model=self.model, max_tokens=2048, system=system, messages=self._messages(history),
            tools=[{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
                   for t in tools],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [{"id": b.id, "name": b.name, "args": b.input} for b in resp.content if b.type == "tool_use"]
        return {"role": "assistant", "text": text, "tool_calls": calls}


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


class ScriptedBackend:
    """Deterministic stand-in for a *naive* LLM, used in tests and CI.

    It does what an injectable agent does: reads the mail, looks up the customer, obeys any
    "send ... to <address>" instruction it finds in the mail or the user's request, then drafts a reply.
    """

    name = "scripted"

    async def next(self, system, history, tools):
        def call(name, args):
            return {"role": "assistant", "text": "", "tool_calls": [{"id": uuid.uuid4().hex[:8], "name": name,
                                                                      "args": args}]}

        done = [m for m in history if m["role"] == "tool"]
        names = [m["name"] for m in done]
        user_text = history[0]["text"]
        if "read_inbox" not in names:
            return call("read_inbox", {"limit": 1})
        mail = done[names.index("read_inbox")]["content"].split("\n\nMessage-ID:")[0]
        sender = re.search(r"^From: (.+)$", mail, re.M).group(1)
        subject = re.search(r"^Subject: (.+)$", mail, re.M).group(1)
        customer_id = re.search(r"C-\d{4}", mail).group(0)
        if "query_customer" not in names:
            return call("query_customer", {"customer_id": customer_id})
        record = done[names.index("query_customer")]["content"]
        body = mail.split("\n\n", 1)[1]
        targets = EMAIL_RE.findall(body) + EMAIL_RE.findall(user_text)
        targets = [t for t in dict.fromkeys(targets) if t != sender]
        sent = sum(1 for n in names if n == "send_email")
        if sent < len(targets):
            to = targets[sent]
            return call("send_email", {"to": to, "subject": f"Customer {customer_id} record",
                                       "body": f"As requested, customer record:\n{record}"})
        return {"role": "assistant", "text": f"Draft reply to {sender}:\n\nDear customer, thank you for "
                f"your message regarding \"{subject}\". We are looking into it and will get back to "
                f"you shortly.\n\nBest regards,\nYour Relationship Manager", "tool_calls": []}


def make_backend(kind: str):
    if kind == "ollama":
        return OllamaBackend()
    if kind == "anthropic":
        return AnthropicBackend()
    if kind == "scripted":
        return ScriptedBackend()
    raise ValueError(f"unknown LLM backend {kind!r}")
