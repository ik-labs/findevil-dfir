#!/usr/bin/env python3
"""
demo_selfcorrection.py — prints the engine's self-correction ladder (miss -> catch) for the two
planted contradictions, then the blind-scored result. Designed for the demo video: a clean,
narratable "live terminal execution" of the required self-correction sequence + accuracy validation.

    python3 demo_selfcorrection.py

Uses the real engine, the injected $MFT bodyfile, and the memory process list — no LLM. The
ground-truth key is read ONLY by the scorer, after the (key-blind) run.
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in ("extractors", "engine", "scoring", "mcp_server"):
    sys.path.insert(0, os.path.join(_HERE, _p))

import tools                       # noqa: E402  (BODYFILE/STRUCTURED + parsers)
import engine as _engine           # noqa: E402
import run_case as _rc             # noqa: E402
import score as _sc                # noqa: E402

C = {"red": "\033[91m", "yel": "\033[93m", "grn": "\033[92m", "cyn": "\033[96m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}
TS, MQ = "104046", "104210"


def _vcolor(v):
    if "confirmed" in v or "masquerade" in v:
        return C["red"]
    if "suspected" in v:
        return C["yel"]
    return C["dim"]


def _ladder(title, trace):
    print(f"\n{C['b']}{C['cyn']}● {title}{C['x']}  "
          f"(caught @ iteration {C['grn']}{trace['caught_at_iteration']}{C['x']})")
    for s in trace["trace"]:
        col = _vcolor(s["working_verdict"])
        tag = ""
        if s["iteration"] == 1 and "benign" in s["working_verdict"]:
            tag = f"  {C['red']}[one-shot MISS]{C['x']}"
        if "confirmed" in s["working_verdict"] or "masquerade" in s["working_verdict"]:
            tag = f"  {C['grn']}[CATCH]{C['x']}"
        print(f"  {C['b']}{s['iteration']}{C['x']} {col}{s['working_verdict']}{C['x']}{tag}")
        print(f"      {s['hypothesis']}")
        print(f"      {C['dim']}↳ self-check: {s['self_check']}{C['x']}")
        if s.get("gap"):
            print(f"      {C['yel']}⚠ gap: {s['gap']}{C['x']}")


def main():
    procs = tools._mem.get_process_list(tools.STRUCTURED)
    ents = tools._ts.parse_bodyfile(tools.BODYFILE)

    rt = ents.get(TS)
    ts_trace = _engine.investigate(rt["path"], tools._ts._iso(rt["si"]["crtime"]),
                                   tools._ts._iso(rt["fn_crtime"]), TS, procs)
    rm = ents.get(MQ)
    mq_trace = _engine.investigate_masquerade("svchost.exe", rm["path"], MQ, procs)

    print(f"{C['b']}FindEvil — self-correction (miss → catch){C['x']}  "
          f"{C['dim']}engine only, no LLM{C['x']}")
    _ladder("timestomp · OneDrive.exe", ts_trace)
    _ladder("masquerade · svchost.exe", mq_trace)

    # key-blind run, then score against the ground-truth key (only the scorer reads it)
    run = _rc.run_case(tools.BODYFILE, tools.STRUCTURED, min_confidence="medium")
    key = json.load(open(os.path.join(_HERE, "scoring", "groundtruth.json")))
    m = _sc.score(run, key)["totals"]
    print(f"\n{C['b']}{C['cyn']}● Accuracy — scored vs a blind ground-truth key{C['x']}")
    print(f"  catch@iter1 = {C['red']}{m['catch_at_iter1']}/{m['injections']} "
          f"({int(m['iter1_catch_rate']*100)}%){C['x']}   →   "
          f"catch@final = {C['grn']}{m['catch_at_final']}/{m['injections']} "
          f"({int(m['final_catch_rate']*100)}%){C['x']}")
    print(f"  {C['grn']}✓{C['x']} {m['false_positives']} false positives   "
          f"{C['grn']}✓{C['x']} {m['false_negatives']} false negatives   "
          f"{C['dim']}({run['candidates_investigated']} candidates scanned){C['x']}")


if __name__ == "__main__":
    main()
