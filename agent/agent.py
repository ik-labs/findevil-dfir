#!/usr/bin/env python3
"""
agent.py — the autonomous DFIR agent (the agentic framework, model-agnostic).

A ReAct-style tool-calling loop that drives the Find Evil! Custom MCP Server. The LLM does the
ORCHESTRATION (which tool to call, how to reason across results); the hard forensic logic lives
in the read-only MCP tools. This satisfies the hackathon's "Custom MCP Server" approach with a
comparable agentic architecture, and is model-agnostic — here it runs on Cerebras (OpenAI-
compatible API: Llama 3.3 70B / Qwen / ...), needing no Claude/Anthropic dependency.

Design notes that matter for the submission:
  * The agent ONLY sees the MCP tools — all read-only. It physically cannot run a shell or
    write to evidence (the server exposes no such tool). Evidence integrity is architectural.
  * Every round (model turn + tool calls + results) is appended to a timestamped transcript
    (submission component #8: agent execution log, every finding traceable to a tool call).
  * A hard --max-rounds cap prevents runaway loops.
  * The system prompt encodes the cross-source methodology (don't trust a single source) so the
    model reproduces the miss->catch reasoning; the deterministic engine remains the oracle.

Env: CEREBRAS_API_KEY (required), CEREBRAS_MODEL (default llama-3.3-70b),
     CEREBRAS_BASE_URL (default https://api.cerebras.ai/v1), FINDEVIL_MCP (server.py path).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from openai import AsyncOpenAI, RateLimitError, APIError
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

DEFAULT_MODEL = os.environ.get("CEREBRAS_MODEL", "gpt-oss-120b")  # available on Cerebras; strong tool-calling
BASE_URL = os.environ.get("CEREBRAS_BASE_URL", "https://api.cerebras.ai/v1")
MCP_SERVER = os.environ.get(
    "FINDEVIL_MCP",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp_server", "server.py"),
)
TOOL_RESULT_CAP = 24000  # chars; our tools return small structured data, this is a safety net

SYSTEM_PROMPT = """You are a principal DFIR analyst working a Windows host on a SANS SIFT \
Workstation. You have a disk image and a memory capture from the SAME machine, exposed ONLY \
through read-only forensic tools. Your job: find EVIL by cross-referencing disk and memory for \
CONTRADICTIONS, and report each with evidence.

Method (non-negotiable):
- Never trust a single source. A file's visible $STANDARD_INFORMATION timestamp is forgeable \
(timestomp T1070.006); a process NAME is forgeable (masquerade T1036).
- Corroborate across sources before concluding: $SI vs $FN creation times, a binary's name vs \
its canonical system path, and whether it is actually executing in memory.
- For every finding cite the artifact that proves it (MFT entry and/or process PID).
- Use the tools to get facts. Do NOT guess or invent artifacts. If a tool already cross-\
references sources (detect_*), use it, but explain the underlying contradiction.
- Assess the intrusion itself, not just tampering: use get_remote_access to determine whether \
activity was LOCAL (console) or REMOTE (an external source IP over RDP) and whether there was \
OUTBOUND RDP (lateral movement); use get_usb_devices for removable-media exfiltration. Cite the \
remote source IP or USB serial as the artifact.

MANDATORY: this is an intrusion investigation, not only a tampering check. You MUST call ALL FOUR \
real-case tools — get_remote_access, get_usb_devices, get_web_activity, and get_program_execution \
— before writing your final report. Do not conclude or output the FINDINGS report until you have \
called them and incorporated their results — finding the contradictions is necessary but NOT \
sufficient. Tie the web downloads (exfil), USB media, remote source IP, and program execution \
together into the exfiltration story.

When done, output a concise FINDINGS report with two parts: (1) each confirmed contradiction — \
file, type (timestomp/masquerade), disk evidence, memory corroboration, provenance; and (2) the \
intrusion picture — local vs remote access (with the remote source IP), any outbound RDP pivot, \
and USB/exfil indicators (with device serials)."""

DEFAULT_TASK = ("Investigate this Windows host (the ROCBA intrusion). Work these steps in order and "
                "do NOT skip any: (1) call get_timestomp_candidates then detect_timestomps; "
                "(2) call detect_masquerade; (3) call get_remote_access (local vs remote, source IPs, "
                "outbound pivot); (4) call get_usb_devices (removable-media exfil); (5) call "
                "get_web_activity (browser downloads / exfil to USB / SharePoint sources); (6) call "
                "get_program_execution (exfil tooling, shells, anti-forensics). Only AFTER all six "
                "steps, output a FINDINGS report covering the disk/memory contradictions AND the "
                "real-case exfiltration kill chain, citing artifacts (IPs, USB serials, URLs, file "
                "paths, MFT entries, PIDs).")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _mcp_tools_to_openai(tools) -> list[dict]:
    out = []
    for t in tools:
        out.append({"type": "function", "function": {
            "name": t.name,
            "description": (t.description or "").strip(),
            "parameters": t.inputSchema or {"type": "object", "properties": {}},
        }})
    return out


async def run(task: str, model: str, max_rounds: int, trace_path: str | None, emit=None) -> dict:
    """emit: optional async callback(event_dict) for live streaming (SSE). Events:
    {type:tools}, {type:thinking,round}, {type:round,round,ts,assistant,tool_calls}."""
    if not os.environ.get("CEREBRAS_API_KEY"):
        raise SystemExit("CEREBRAS_API_KEY not set — export it (the box must have the key).")
    client = AsyncOpenAI(base_url=BASE_URL, api_key=os.environ["CEREBRAS_API_KEY"], max_retries=0)

    async def _emit(ev):
        if emit:
            await emit(ev)

    def _round_ev(rl):
        return {"type": "round", "round": rl["round"], "ts": rl["ts"], "assistant": rl["assistant"],
                "token_usage": rl.get("token_usage"),
                "tool_calls": [{"name": c["name"], "args": c["args"],
                                "result_preview": c["result_preview"][:300]} for c in rl["tool_calls"]]}

    async def _complete(**kw):
        """Cerebras' free tier returns 429 'queue_exceeded' under load — retry with backoff."""
        delay = 4.0
        for attempt in range(8):
            try:
                return await client.chat.completions.create(**kw)
            except (RateLimitError, APIError) as e:
                if attempt == 7:
                    raise
                sys.stderr.write(f"[retry {attempt+1}/8 in {delay:.0f}s: {type(e).__name__}]\n")
                await asyncio.sleep(delay)
                delay = min(delay * 1.6, 30)

    transcript = {"started": _now(), "model": model, "task": task, "rounds": [],
                  "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
    params = StdioServerParameters(command="python3", args=[MCP_SERVER])

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = _mcp_tools_to_openai((await session.list_tools()).tools)
            transcript["tools_available"] = [t["function"]["name"] for t in tools]
            await _emit({"type": "tools", "model": model, "tools": transcript["tools_available"]})

            messages = [{"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": task}]
            final = None

            for rnd in range(1, max_rounds + 1):
                await _emit({"type": "thinking", "round": rnd})
                resp = await _complete(
                    model=model, messages=messages, tools=tools, tool_choice="auto", temperature=0)
                msg = resp.choices[0].message
                _u = getattr(resp, "usage", None)
                usage = ({"prompt_tokens": getattr(_u, "prompt_tokens", None),
                          "completion_tokens": getattr(_u, "completion_tokens", None),
                          "total_tokens": getattr(_u, "total_tokens", None)} if _u else None)
                if usage:
                    for _k in transcript["token_usage"]:
                        transcript["token_usage"][_k] += usage.get(_k) or 0
                round_log = {"round": rnd, "ts": _now(), "assistant": msg.content,
                             "tool_calls": [], "token_usage": usage}

                assistant_entry = {"role": "assistant", "content": msg.content or ""}
                if msg.tool_calls:
                    assistant_entry["tool_calls"] = [
                        {"id": tc.id, "type": "function",
                         "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in msg.tool_calls]
                messages.append(assistant_entry)

                if not msg.tool_calls:
                    final = msg.content
                    transcript["rounds"].append(round_log)
                    await _emit(_round_ev(round_log))
                    break

                for tc in msg.tool_calls:
                    name = tc.function.name
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    try:
                        res = await session.call_tool(name, args)
                        text = res.content[0].text if res.content else "{}"
                    except Exception as e:  # noqa: BLE001 - surface tool errors to the model
                        text = json.dumps({"error": str(e)})
                    text = text[:TOOL_RESULT_CAP]
                    round_log["tool_calls"].append({"name": name, "args": args, "result_preview": text[:800]})
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})

                transcript["rounds"].append(round_log)
                await _emit(_round_ev(round_log))
            else:
                final = "[stopped: max rounds reached without a final report]"

    transcript["final_report"] = final
    transcript["ended"] = _now()
    if trace_path:
        os.makedirs(os.path.dirname(trace_path), exist_ok=True)
        with open(trace_path, "w") as fh:
            json.dump(transcript, fh, indent=2)
    return transcript


def _main() -> int:
    ap = argparse.ArgumentParser(description="Autonomous DFIR agent over the Find Evil! MCP server (Cerebras).")
    ap.add_argument("--task", default=DEFAULT_TASK)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-rounds", type=int, default=8)
    ap.add_argument("--trace-out", default=None, help="write the full agent execution log here (#8)")
    ap.add_argument("--quiet", action="store_true", help="only print the final report")
    args = ap.parse_args()

    async def _printer(ev):
        """Stream the run live to the terminal (round by round) — good for the screencast."""
        et = ev.get("type")
        if et == "tools":
            print(f"MCP server up · {len(ev['tools'])} read-only tools offered to {ev.get('model')}", flush=True)
        elif et == "thinking":
            print(f"\n── round {ev['round']} · querying model…", flush=True)
        elif et == "round":
            tu = ev.get("token_usage") or {}
            tok = f"   [tokens: {tu.get('total_tokens','?')}]" if tu else ""
            for c in ev.get("tool_calls", []):
                print(f"  → {c['name']}({json.dumps(c['args'])}){tok}", flush=True)
                print(f"    {c['result_preview'][:220].replace(chr(10), ' ')}", flush=True)

    t = asyncio.run(run(args.task, args.model, args.max_rounds, args.trace_out,
                        emit=(None if args.quiet else _printer)))
    tt = t.get("token_usage") or {}
    print("\n================ FINAL REPORT ================\n")
    print(t["final_report"])
    print(f"\n[execution log] rounds: {len(t['rounds'])} · "
          f"total tokens: {tt.get('total_tokens','?')} "
          f"(prompt {tt.get('prompt_tokens','?')} / completion {tt.get('completion_tokens','?')}) · "
          f"trace: {args.trace_out or '(not saved)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
