#!/usr/bin/env python3
"""
run_case.py — produce a RUN OUTPUT: the system's findings on a case, with per-iteration
verdicts from the self-correction engine. This stands in for "the agent's output".

CRITICAL (anti-leakage): this script NEVER reads scoring/groundtruth.json. It only runs the
detection pipeline + engine and records what they concluded. Grading is a SEPARATE step
(score.py) that compares this output to the key. The system being graded must not see the key.

For each disk timestomp candidate (>= min_confidence) it runs the engine and records the
accuracy curve (verdict per iteration), the final verdict, and the catch iteration.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "extractors"))
sys.path.insert(0, os.path.join(_HERE, "..", "engine"))

import timestomp as _ts            # noqa: E402
import masquerade as _mq            # noqa: E402
from memory import get_process_list, basename  # noqa: E402
from engine import investigate, investigate_masquerade  # noqa: E402


def _record(r: dict, ctype: str) -> dict:
    return {"type": ctype, "target": r["target"], "mft_entry": r["mft_entry"],
            "final_verdict": r["final_verdict"], "caught_at_iteration": r["caught_at_iteration"],
            "accuracy_curve": r["accuracy_curve"]}


def run_case(bodyfile: str, memory_source: str, min_confidence: str = "medium",
             max_iterations: int = 5) -> dict:
    procs = get_process_list(memory_source)
    findings = []

    # timestomp candidates -> engine
    res = _ts.get_timestomp_candidates(bodyfile)
    keep = {"high": ["high"], "medium": ["high", "medium"],
            "all": ["high", "medium", "low"]}.get(min_confidence, ["high", "medium"])
    for c in [c for c in res["candidates"] if c["confidence"] in keep]:
        r = investigate(c["path"], c["si_crtime"], c["fn_crtime"], c["mft_entry"], procs, max_iterations)
        findings.append(_record(r, "timestomp"))

    # masquerade candidates (disk + memory) -> engine
    for d in _mq.scan_disk(bodyfile):
        r = investigate_masquerade(d["name"], d["path"], d["mft_entry"], procs, max_iterations)
        findings.append(_record(r, "masquerade"))
    for m in _mq.scan_memory(procs):
        r = investigate_masquerade(m["name"], m["path"], f"pid:{m['pid']}", procs, max_iterations)
        findings.append(_record(r, "masquerade"))
    return {
        "case": os.path.basename(bodyfile),
        "min_confidence": min_confidence,
        "max_iterations": max_iterations,
        "candidates_investigated": len(findings),
        "findings": findings,
    }


def _main() -> int:
    ap = argparse.ArgumentParser(description="Produce a run output (no ground-truth access).")
    ap.add_argument("bodyfile")
    ap.add_argument("memory_source")
    ap.add_argument("--min-confidence", choices=["high", "medium", "all"], default="medium")
    ap.add_argument("--max-iterations", type=int, default=5)
    ap.add_argument("--out", required=True, help="write run output JSON here")
    args = ap.parse_args()
    result = run_case(args.bodyfile, args.memory_source, args.min_confidence, args.max_iterations)
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"run output -> {args.out}  ({result['candidates_investigated']} candidates investigated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
