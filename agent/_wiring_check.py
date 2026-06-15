"""Smoke-test the agent's MCP wiring without calling the LLM (no API key needed)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent import _mcp_tools_to_openai, MCP_SERVER
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(command="python3", args=[MCP_SERVER])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = _mcp_tools_to_openai((await s.list_tools()).tools)
            print("MCP server:", os.path.basename(MCP_SERVER))
            print("tools exposed to the model:", len(tools))
            for t in tools:
                f = t["function"]
                params_list = list((f["parameters"] or {}).get("properties", {}).keys())
                print("  - {}({})".format(f["name"], ", ".join(params_list)))
            assert all(t["type"] == "function" and "name" in t["function"] for t in tools)
            # no write/exec tool is reachable by the agent
            names = {t["function"]["name"] for t in tools}
            assert not any(b in n for n in names for b in ("shell", "exec", "write", "delete")), names
            print("schema shape: VALID for Cerebras/OpenAI tool-calling")
            print("write/exec tools reachable by agent: NONE (read-only surface)")


asyncio.run(main())
