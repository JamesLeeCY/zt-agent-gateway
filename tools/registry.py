"""MCP server registry and a small client pool used by both the gateway and the direct-mode agent."""
import json
import os
import sys
from contextlib import AsyncExitStack

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

from tools.paths import ROOT

SERVERS = ["tools.inbox_server", "tools.customer_server", "tools.email_server"]

# Arguments the runtime binds from the authenticated subject; never chosen by the LLM.
BOUND_ARGS = {"read_inbox": {"mailbox": "on_behalf_of"}}


class McpPool:
    """Keeps one stdio session per MCP server and routes tool calls by name."""

    def __init__(self, servers: list[str] = SERVERS):
        self._servers = servers
        self._stack = AsyncExitStack()
        self._route: dict[str, ClientSession] = {}
        self.tools: list[dict] = []

    async def __aenter__(self):
        # stdio_client only passes a minimal environment; forward our own settings explicitly.
        env = {**get_default_environment(), **{k: v for k, v in os.environ.items() if k.startswith("ZT_")}}
        for module in self._servers:
            params = StdioServerParameters(command=sys.executable, args=["-m", module], cwd=str(ROOT), env=env)
            read, write = await self._stack.enter_async_context(stdio_client(params))
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            for tool in (await session.list_tools()).tools:
                self._route[tool.name] = session
                self.tools.append(
                    {"name": tool.name, "description": tool.description, "input_schema": tool.inputSchema}
                )
        return self

    async def __aexit__(self, *exc):
        await self._stack.aclose()

    def has_tool(self, name: str) -> bool:
        return name in self._route

    async def call(self, name: str, args: dict) -> str:
        result = await self._route[name].call_tool(name, args)
        text = "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")
        if result.isError:
            return json.dumps({"error": text})
        return text


def agent_visible_tools(tools: list[dict]) -> list[dict]:
    """Hide runtime-bound arguments from the schemas the LLM sees."""
    visible = []
    for t in tools:
        schema = json.loads(json.dumps(t["input_schema"]))
        for arg in BOUND_ARGS.get(t["name"], {}):
            schema.get("properties", {}).pop(arg, None)
            if arg in schema.get("required", []):
                schema["required"].remove(arg)
        visible.append({**t, "input_schema": schema})
    return visible
