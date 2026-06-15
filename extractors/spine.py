#!/usr/bin/env python3
"""
spine.py — the cross-source join: corroborate disk timestomp candidates against memory.

This is the SPINE of the thesis. The disk half (timestomp.py) finds files whose visible
$SI creation is backdated vs the true $FN creation. But disk alone can't separate a
malicious timestomp from a benign vendor-bundled file (build-date < install-date) — both
look "backdated". The discriminator is EXECUTION:

    a real timestomp's file is RUNNING, and its process started at the true-recent time
    (≈ $FN), nowhere near the forged-old $SI. A dormant vendor DLL is not running.

So we join each candidate's disk path to the in-memory process list (by normalized launch
path, basename as fallback) and compare the process start time to $SI vs $FN.

Verdicts (escalating):
  confirmed_timestomp   process runs from this path; start ≈ $FN and FAR from forged $SI.
                        Three-leg contradiction (disk $SI vs disk $FN vs memory start). CRITICAL.
  running_ambiguous     a process runs from this path but its start is near $SI — $SI may be
                        genuine; needs a human / more signal.
  basename_match_only   a process with the same exe name runs from a DIFFERENT path — could be
                        masquerade; flag, lower confidence.
  no_execution          backdated file is not running. Not corroborated; in an install dir this
                        is the benign vendor-bundle pattern, elsewhere a dormant-payload lead.

Every finding carries provenance for BOTH sources ($MFT entry + _EPROCESS PID) — the audit trail.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from timestomp import get_timestomp_candidates, USER_WRITABLE_PATTERNS  # noqa: E402
from memory import get_process_list, normalize_path, basename  # noqa: E402

# How far a process start may sit from $FN and still count as "≈ $FN" (the true recent time).
NEAR_FN_DAYS = 14
# How far the process start must sit ABOVE $SI to treat $SI as forged-old.
SI_FORGED_MIN_DAYS = 30
# Execution alone is not enough: legit vendor software routinely has build-date($SI) <
# install-date($FN) by days/weeks AND auto-starts (Adobe armsvc, Zoom, etc.). We only call a
# RUNNING backdated file a confirmed timestomp if the backdating is implausible for a vendor
# build/install gap — i.e. a large backdate OR a user-writable (payload-drop) location. The
# fully robust discriminator is Authenticode signing (a future extractor).
CONFIRM_BACKDATE_DAYS = 365


def _user_writable(path: str) -> bool:
    low = "/" + normalize_path(path)
    return any(p in low for p in USER_WRITABLE_PATTERNS)


def _parse(ts: str | None):
    if not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _days(a, b):
    return abs((a - b).total_seconds()) / 86400.0 if a and b else None


def corroborate(candidates: list[dict], processes: list[dict]) -> list[dict]:
    by_path: dict[str, list[dict]] = {}
    by_base: dict[str, list[dict]] = {}
    for p in processes:
        if p["norm_path"]:
            by_path.setdefault(p["norm_path"], []).append(p)
            by_base.setdefault(basename(p["norm_path"]), []).append(p)

    findings = []
    for c in candidates:
        cpath = normalize_path(c["path"])
        cbase = basename(c["path"])
        si, fn = _parse(c["si_crtime"]), _parse(c["fn_crtime"])

        path_hits = by_path.get(cpath, [])
        base_hits = [p for p in by_base.get(cbase, []) if p["norm_path"] != cpath]

        verdict, matched, reason = "no_execution", None, ""
        if path_hits:
            matched = min(path_hits, key=lambda p: p["start"] or "9999")
            start = _parse(matched["start"])
            d_si = _days(start, si)
            d_fn = _days(start, fn)
            running_backdated = (start and d_si is not None and d_si >= SI_FORGED_MIN_DAYS
                                 and (d_fn is None or d_fn <= NEAR_FN_DAYS or start >= fn))
            if running_backdated:
                strong = c["backdate_days"] >= CONFIRM_BACKDATE_DAYS or _user_writable(c["path"])
                if strong:
                    verdict = "confirmed_timestomp"
                    reason = (f"process (pid {matched['pid']}) runs from this path, started {matched['start']} "
                              f"— {d_si:.0f}d after the forged $SI but ~{(d_fn or 0):.0f}d from the true $FN, "
                              f"and the backdating is implausible for a vendor build/install gap "
                              f"({c['backdate_days']:.0f}d{' / user-writable path' if _user_writable(c['path']) else ''}). "
                              f"Disk backdating corroborated by live execution.")
                else:
                    verdict = "running_vendor_pattern"
                    reason = (f"process (pid {matched['pid']}) runs from this path, but the {c['backdate_days']:.0f}d "
                              f"$SI<$FN gap in a vendor install dir is the normal build-date<install-date pattern "
                              f"— likely benign (verify code signature to confirm).")
            else:
                verdict = "running_ambiguous"
                reason = (f"process (pid {matched['pid']}) runs from this path but started near $SI; "
                          f"$SI may be genuine.")
        elif base_hits:
            verdict, matched = "basename_match_only", base_hits[0]
            reason = (f"a process named '{cbase}' runs from a DIFFERENT path "
                      f"({matched['norm_path']}) — possible masquerade, not this file executing.")
        else:
            reason = "backdated file is not running in memory; no execution corroboration."

        prov = [c["provenance"]]
        if matched:
            prov.append(matched["provenance"])
        findings.append({
            "path": c["path"],
            "disk_confidence": c["confidence"],
            "verdict": verdict,
            "backdate_days": c["backdate_days"],
            "si_crtime": c["si_crtime"],
            "fn_crtime": c["fn_crtime"],
            "memory": None if not matched else {
                "matched_pid": matched["pid"],
                "process_start": matched["start"],
                "process_path": matched["norm_path"],
            },
            "reasoning": reason,
            "provenance": prov,
        })

    order = {"confirmed_timestomp": 0, "basename_match_only": 1, "running_ambiguous": 2,
             "running_vendor_pattern": 3, "no_execution": 4}
    findings.sort(key=lambda f: (order[f["verdict"]], -f["backdate_days"]))
    return findings


def detect_timestomps(bodyfile: str, memory_source: str, min_confidence: str = "high",
                      min_delta_days: float = 1.0) -> dict:
    """Full timestomp pipeline: disk candidates -> memory corroboration -> ranked findings."""
    tc = get_timestomp_candidates(bodyfile, min_delta_days=min_delta_days)
    levels = {"high": ["high"], "medium": ["high", "medium"], "all": ["high", "medium", "low"]}
    keep = levels.get(min_confidence, ["high"])
    cands = [c for c in tc["candidates"] if c["confidence"] in keep]
    procs = get_process_list(memory_source)
    findings = corroborate(cands, procs)
    vcount: dict[str, int] = {}
    for f in findings:
        vcount[f["verdict"]] = vcount.get(f["verdict"], 0) + 1
    return {
        "summary": {
            "disk_candidates_considered": len(cands),
            "processes_with_path": sum(1 for p in procs if p["norm_path"]),
            "by_verdict": vcount,
        },
        "findings": findings,
    }


def _main() -> int:
    ap = argparse.ArgumentParser(description="Timestomp spine: disk $SI/$FN + memory corroboration.")
    ap.add_argument("bodyfile", help="TSK bodyfile (sudo fls -r -m C: <image>)")
    ap.add_argument("memory_source", help=".raw memory image | dir of cached vol json")
    ap.add_argument("--min-confidence", choices=["high", "medium", "all"], default="high")
    ap.add_argument("--min-delta-days", type=float, default=1.0)
    args = ap.parse_args()
    result = detect_timestomps(args.bodyfile, args.memory_source,
                               args.min_confidence, args.min_delta_days)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
