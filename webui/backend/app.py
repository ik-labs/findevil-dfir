#!/usr/bin/env python3
"""
app.py — FastAPI backend for the Find Evil! dashboard. Thin wrapper: every endpoint just calls
functions we already built and tested (the MCP tools / engine / scorer) and returns JSON. No new
forensic logic. Serves the single-file React dashboard too.

Run on the box:  uvicorn app:app --host 127.0.0.1 --port 8000
Then from your Mac:  ssh -L 8000:localhost:8000 rocba  ->  open http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from functools import lru_cache

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))          # findevil/
for _p in ("extractors", "engine", "scoring", "mcp_server", "agent"):
    sys.path.insert(0, os.path.join(_REPO, _p))

import tools                       # mcp_server/tools.py — audited, read-only
import engine as _engine           # engine/engine.py
import run_case as _rc             # scoring/run_case.py
import score as _sc                # scoring/score.py
import agent as _agent             # agent/agent.py — Cerebras ReAct driver

_AGENT_LOCK = asyncio.Lock()       # serialize live runs (free-tier rate limits)


def _load_cerebras_env():
    """Load CEREBRAS_API_KEY from the box's env file (outside the repo) if not already set."""
    envf = os.path.join(CASE, ".cerebras.env")
    if not os.environ.get("CEREBRAS_API_KEY") and os.path.exists(envf):
        for line in open(envf):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"

CASE = os.environ.get("FINDEVIL_CASE", os.path.expanduser("~/cases/rocba"))
BODYFILE, STRUCTURED = tools.BODYFILE, tools.STRUCTURED
GROUNDTRUTH = os.path.join(_REPO, "scoring", "groundtruth.json")
AGENT_TRACE = os.path.join(CASE, "output/traces/agent-run.json")

app = FastAPI(title="Find Evil! DFIR Dashboard")


@app.get("/api/overview")
def overview():
    evidence = []
    evdir = os.path.join(CASE, "evidence")
    for f in sorted(os.listdir(evdir)):
        st = os.stat(os.path.join(evdir, f))
        evidence.append({"name": f, "gb": round(st.st_size / 1e9, 2),
                         "readonly": not bool(st.st_mode & 0o222)})
    names = list(tools.READ_ONLY_TOOLS)
    write_like = [t for t in names if any(b in t.lower() for b in ("write", "exec", "shell", "delete", "run_"))]
    return {
        "case": "ROCBA — Fred Rocba (SANS FOR500)", "host": "Windows 10 build 19041 x64",
        "memory_capture": "2020-11-16 02:32:38 UTC", "vacation_window": "2020-11-10 → 11-13",
        "evidence": evidence, "tools": names, "write_tools": write_like,
        "integrity": {"originals_readonly": all(e["readonly"] for e in evidence),
                      "write_or_exec_tools": len(write_like)},
    }


@app.get("/api/detect")
def detect():
    return {"timestomp": tools.detect_timestomps("high"), "masquerade": tools.detect_masquerade()}


@app.get("/api/casefindings")
def casefindings():
    """Real-case intrusion intel straight from the read-only MCP tools (USB + remote access).
    Distinct from the scored planted-contradiction detector; these are genuine ROCBA artifacts."""
    return {"usb": tools.get_usb_devices(), "remote": tools.get_remote_access(),
            "web": tools.get_web_activity(), "execution": tools.get_program_execution()}


@app.get("/api/traces")
def traces():
    procs = tools._mem.get_process_list(STRUCTURED)
    ents = tools._ts.parse_bodyfile(BODYFILE)

    def ts_trace(entry):
        rec = ents.get(str(entry))
        return _engine.investigate(rec["path"], tools._ts._iso(rec["si"]["crtime"]),
                                   tools._ts._iso(rec["fn_crtime"]), str(entry), procs)

    def mq_trace(entry, name):
        rec = ents.get(str(entry))
        return _engine.investigate_masquerade(name, rec["path"], str(entry), procs)

    return {"timestomp": ts_trace(104046), "masquerade": mq_trace(104210, "svchost.exe")}


@lru_cache(maxsize=1)
def _scored():
    run = _rc.run_case(BODYFILE, STRUCTURED, min_confidence="medium")
    key = json.load(open(GROUNDTRUTH))
    return {"metrics": _sc.score(run, key), "key": key, "candidates": run["candidates_investigated"]}


@app.get("/api/score")
def score():
    return _scored()


@app.get("/api/audit")
def audit(n: int = 30):
    try:
        lines = [json.loads(x) for x in open(tools.AUDIT_LOG)][-n:]
    except (FileNotFoundError, json.JSONDecodeError):
        lines = []
    return {"audit": lines}


@app.get("/api/agent")
def agent():
    """Return the saved autonomous-agent transcript (component #8). Reliable fallback for the demo."""
    try:
        return json.load(open(AGENT_TRACE))
    except FileNotFoundError:
        return {"error": "no saved agent run yet"}


@app.get("/api/agent/stream")
async def agent_stream():
    """Run the Cerebras agent LIVE and stream each round as Server-Sent Events. The client
    replays these into the console; on any error the client falls back to /api/agent (saved run)."""
    async def gen():
        _load_cerebras_env()
        if not os.environ.get("CEREBRAS_API_KEY"):
            yield _sse({"type": "error", "error": "CEREBRAS_API_KEY not configured on server"})
            yield _sse({"type": "done"})
            return

        q: asyncio.Queue = asyncio.Queue()

        async def emit(ev):
            await q.put(ev)

        async def driver():
            async with _AGENT_LOCK:
                try:
                    t = await _agent.run(_agent.DEFAULT_TASK, _agent.DEFAULT_MODEL, 8, AGENT_TRACE, emit=emit)
                    await q.put({"type": "final", "model": t.get("model"), "report": t.get("final_report")})
                except Exception as e:  # noqa: BLE001 — surface to the UI, which falls back
                    await q.put({"type": "error", "error": f"{type(e).__name__}: {e}"})
                finally:
                    await q.put({"type": "done"})

        task = asyncio.create_task(driver())
        try:
            while True:
                ev = await q.get()
                yield _sse(ev)
                if ev.get("type") == "done":
                    break
        finally:
            task.cancel()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


_static = os.path.join(_HERE, "..", "static")
app.mount("/", StaticFiles(directory=_static, html=True), name="static")
