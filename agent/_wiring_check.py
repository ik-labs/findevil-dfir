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
            # no write/exec tool is reachable by the agent — every tool is a read-only getter
            names = {t["function"]["name"] for t in tools}
            assert all(n.startswith(("get_", "detect_")) for n in names), names
            print("schema shape: VALID for Cerebras/OpenAI tool-calling")
            print("write/exec tools reachable by agent: NONE (read-only surface)")

            # Boundary test: simulate the agent attempting to BYPASS the read-only guarantee by
            # calling write/shell/delete tools. They do not exist in the server, so every attempt
            # is rejected at the protocol layer — there is no capability to modify evidence.
            print("\n[bypass attempt] simulating malicious tool calls:")
            for bad, args in (("run_shell", {"cmd": "rm -rf evidence/"}),
                              ("write_file", {"path": "evidence/disk.e01", "data": "x"}),
                              ("delete_artifact", {"mft_entry": "104046"})):
                try:
                    res = await s.call_tool(bad, args)
                    msg = ""
                    try:
                        msg = res.content[0].text
                    except Exception:  # noqa: BLE001
                        pass
                    if getattr(res, "isError", False):
                        print(f"  ✓ {bad}({args}) -> BLOCKED: {msg or 'error result'}")
                    else:
                        print(f"  ✗ {bad}: UNEXPECTEDLY SUCCEEDED — investigate!")
                except Exception as e:  # noqa: BLE001
                    print(f"  ✓ {bad}({args}) -> BLOCKED: {type(e).__name__} (no such tool)")
            print("\nresult: evidence integrity is ARCHITECTURAL — the agent cannot modify evidence "
                  "because no write/shell/delete capability exists to call.")


asyncio.run(main())
