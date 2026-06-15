#!/usr/bin/env python3
"""
engine.py — the self-correction loop (the ENGINE). Turns a one-shot "it looks benign" MISS
into a corroborated CATCH by recognising its own incomplete reasoning and deepening the
investigation one evidence source at a time, with a HARD iteration cap and a full timestamped
trace (submission component #8 + the demo climax).

Why this exists
---------------
A one-shot agent grabs the obvious field ($STANDARD_INFORMATION creation time), sees an old
date, and moves on — exactly how timestomping evades timeline analysis. The engine instead
runs:  attempt -> self-check -> (if a check fails) log the gap -> adjust (pull one more
source) -> re-run, terminating only when the finding is fully corroborated across sources or
the --max-iterations cap is hit (then it reports "unresolved — needs human", never a guess).

Evidence ladder for timestomp (each rung = one self-correction step):
  1. $SI creation alone            -> naive read; an old $SI reads as "benign aged file" (MISS)
  2. + $FN creation (compare)      -> $SI vs $FN mismatch => suspected backdating (disk-internal)
  3. + memory (live process start) -> execution proves true-recent creation => CONFIRMED

The self-check encodes forensic methodology: a creation-time judgement from $SI ALONE is
invalid ($SI is attacker-forgeable); a disk-only backdating claim is stronger if execution
corroborates the true ($FN) time. Each rung the engine names the gap and closes it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "extractors"))
from timestomp import parse_bodyfile, _iso  # noqa: E402
from memory import get_process_list, normalize_path, basename  # noqa: E402
from spine import corroborate  # noqa: E402

MAX_ITERATIONS_DEFAULT = 5


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _days(a_iso: str, b_iso: str) -> float | None:
    try:
        a = datetime.fromisoformat(a_iso.replace("Z", "+00:00"))
        b = datetime.fromisoformat(b_iso.replace("Z", "+00:00"))
        return abs((a - b).total_seconds()) / 86400.0
    except (ValueError, AttributeError):
        return None


def investigate(target_path: str, si_iso: str, fn_iso: str, mft_entry: str,
                processes: list[dict], max_iterations: int = MAX_ITERATIONS_DEFAULT) -> dict:
    """Run the self-correction loop on one file. Returns verdict + full iteration trace."""
    trace: list[dict] = []
    verdict, caught_iter, terminated = "benign", None, "max_iterations"

    # what the agent "knows" grows by one source per iteration
    for it in range(1, max_iterations + 1):
        depth = it
        step = {"iteration": it, "timestamp": _now()}

        if depth == 1:
            # naive: only the visible $SI creation time
            step["action"] = "read $SI (visible) creation time"
            step["observation"] = {"si_creation": si_iso}
            step["hypothesis"] = (f"{basename(target_path)} created {si_iso} — an aged file, "
                                  f"nothing anomalous on its face.")
            step["working_verdict"] = "benign"
            step["self_check"] = ("Conclusion rests on $SI ALONE, which is attacker-forgeable "
                                  "(timestomp targets exactly this field). Corroborated by $FN?")
            step["gap"] = "single-source creation time; $FILE_NAME not yet consulted"
            step["complete"] = False
            verdict = "benign"

        elif depth == 2:
            # adjust: pull $FN and compare
            step["action"] = "read $FN creation time and compare to $SI"
            step["observation"] = {"si_creation": si_iso, "fn_creation": fn_iso}
            d = _days(si_iso, fn_iso)
            if d and d > 1:
                step["hypothesis"] = (f"$SI ({si_iso}) contradicts $FN ({fn_iso}); $SI appears "
                                      f"backdated by ~{d:.0f} days. Suspected timestomp (T1070.006).")
                step["working_verdict"] = "suspected_timestomp"
                step["self_check"] = ("Disk shows backdating, but is the file actually recent and "
                                      "in use? Corroborate the true ($FN) time against runtime (memory).")
                step["gap"] = "no runtime corroboration; memory (process execution) not yet checked"
                step["complete"] = False
                verdict = "suspected_timestomp"
            else:
                step["hypothesis"] = "$SI and $FN agree; no backdating."
                step["working_verdict"] = "benign"
                step["self_check"] = "Creation time corroborated across $SI and $FN."
                step["gap"] = None
                step["complete"] = True
                verdict, terminated = "benign", "resolved"

        else:
            # adjust: corroborate against memory (the spine join)
            step["action"] = "query memory for a live process executing from this path"
            cand = {"path": target_path, "confidence": "high",
                    "backdate_days": round((_days(si_iso, fn_iso) or 0), 2),
                    "si_crtime": si_iso, "fn_crtime": fn_iso,
                    "provenance": f"$MFT entry {mft_entry}: $SI.crtime vs $FN.crtime"}
            finding = corroborate([cand], processes)[0]
            step["observation"] = {"memory": finding["memory"], "join_verdict": finding["verdict"]}
            step["hypothesis"] = finding["reasoning"]
            step["working_verdict"] = finding["verdict"]
            if finding["verdict"] == "confirmed_timestomp":
                step["self_check"] = ("Three independent sources agree the file is recent and its "
                                      "$SI is forged: disk $SI vs disk $FN vs memory process start. Complete.")
                step["gap"] = None
                step["complete"] = True
                verdict, caught_iter, terminated = "confirmed_timestomp", it, "resolved"
                step["provenance"] = finding["provenance"]
            else:
                step["self_check"] = "Execution not corroborated; finding remains disk-only."
                step["gap"] = "no live process from this path; cannot escalate to confirmed"
                step["complete"] = True
                verdict, terminated = finding["verdict"], "resolved"

        trace.append(step)
        if step["complete"]:
            break
    else:
        terminated = "max_iterations"

    if terminated == "max_iterations":
        verdict = f"unresolved ({verdict}) — needs human"

    return {
        "target": target_path,
        "mft_entry": mft_entry,
        "final_verdict": verdict,
        "caught_at_iteration": caught_iter,
        "iterations_run": len(trace),
        "max_iterations": max_iterations,
        "terminated": terminated,
        "accuracy_curve": [{"iteration": s["iteration"], "verdict": s["working_verdict"]} for s in trace],
        "trace": trace,
    }


def investigate_masquerade(name: str, path: str, mft_entry: str, processes: list[dict],
                           max_iterations: int = MAX_ITERATIONS_DEFAULT) -> dict:
    """Self-correction loop for masquerade (T1036): iter1 trusts the NAME (the blind spot),
    iter2 checks the PATH against the canonical system location (+ execution) = the catch."""
    import masquerade as _mq
    canon = sorted(_mq.SYSTEM_BINARIES.get(name.lower(), set()))
    norm = normalize_path(path)
    trace: list[dict] = []
    verdict, caught_iter, terminated = "benign", None, "resolved"

    for it in range(1, max_iterations + 1):
        step = {"iteration": it, "timestamp": _now()}
        if it == 1:
            step["action"] = "identify the binary by name"
            step["observation"] = {"name": name}
            step["hypothesis"] = f"{name} is a known Windows system binary — trusted, benign on its face."
            step["working_verdict"] = "benign"
            step["self_check"] = ("Trust here is NAME-based (the exact blind spot masquerade abuses). "
                                  "Is the file's LOCATION the canonical system path?")
            step["gap"] = "location not verified against the canonical system path"
            step["complete"] = False
            verdict = "benign"
        else:
            step["action"] = "compare actual path to canonical system location (+ check execution)"
            step["observation"] = {"path": norm, "expected": canon}
            running = next((p for p in processes if p["norm_path"] == norm and p["name"].lower() == name.lower()), None)
            if norm in _mq.SYSTEM_BINARIES.get(name.lower(), set()):
                step["hypothesis"] = f"{name} is in its canonical location — legitimate."
                step["working_verdict"] = "benign"
                step["self_check"] = "Name and canonical path agree."
                step["complete"] = True
                verdict = "benign"
            elif running:
                step["hypothesis"] = (f"{name} runs (pid {running['pid']}) from {norm}, not its canonical "
                                      f"{canon} — masquerading system binary, executing.")
                step["working_verdict"] = "confirmed_masquerade"
                step["self_check"] = "Name says system binary; path AND live execution contradict it. Complete."
                step["complete"] = True
                verdict, caught_iter = "confirmed_masquerade", it
                step["provenance"] = [f"$MFT entry {mft_entry} (wrong path)", running["provenance"]]
            else:
                step["hypothesis"] = (f"{name} sits at {norm}, not its canonical {canon} — masquerade "
                                      f"by name+location (T1036); not seen running.")
                step["working_verdict"] = "masquerade"
                step["self_check"] = "Name+path contradict; no execution seen — disk-resident masquerade."
                step["complete"] = True
                verdict, caught_iter = "masquerade", it
                step["provenance"] = [f"$MFT entry {mft_entry} (basename is a system binary, wrong path)"]
            step["gap"] = None
        trace.append(step)
        if step["complete"]:
            break
    else:
        terminated, verdict = "max_iterations", f"unresolved ({verdict}) — needs human"

    return {
        "target": path, "mft_entry": mft_entry, "final_verdict": verdict,
        "caught_at_iteration": caught_iter, "iterations_run": len(trace),
        "max_iterations": max_iterations, "terminated": terminated,
        "accuracy_curve": [{"iteration": s["iteration"], "verdict": s["working_verdict"]} for s in trace],
        "trace": trace,
    }


def _lookup_times(bodyfile: str, mft_entry: int | None, path_substr: str | None) -> dict:
    entries = parse_bodyfile(bodyfile)
    if mft_entry is not None:
        rec = entries.get(str(mft_entry))
        if not rec or not rec["si"] or rec["fn_crtime"] is None:
            raise SystemExit(f"entry {mft_entry} not found / missing $SI or $FN")
        return {"path": rec["path"], "entry": str(mft_entry),
                "si": _iso(rec["si"]["crtime"]), "fn": _iso(rec["fn_crtime"])}
    for e, rec in entries.items():
        if path_substr and rec["path"] and path_substr.lower() in rec["path"].lower() \
                and rec["si"] and rec["fn_crtime"] is not None:
            return {"path": rec["path"], "entry": e,
                    "si": _iso(rec["si"]["crtime"]), "fn": _iso(rec["fn_crtime"])}
    raise SystemExit("target not found in bodyfile")


def _narrate(result: dict) -> str:
    L = [f"=== SELF-CORRECTION ENGINE — investigating {result['target']} ===",
         f"(MFT entry {result['mft_entry']}, max_iterations={result['max_iterations']})", ""]
    for s in result["trace"]:
        L.append(f"[iter {s['iteration']}] {s['timestamp']}")
        L.append(f"  ACTION    : {s['action']}")
        L.append(f"  HYPOTHESIS: {s['hypothesis']}")
        L.append(f"  VERDICT   : {s['working_verdict']}")
        L.append(f"  SELF-CHECK: {s['self_check']}")
        if s.get("gap"):
            L.append(f"  GAP       : {s['gap']}  -> adjust & re-run")
        L.append("")
    arrow = " -> ".join(p["verdict"] for p in result["accuracy_curve"])
    L.append(f"ACCURACY CURVE : {arrow}")
    L.append(f"FINAL VERDICT  : {result['final_verdict']}"
             + (f"  (caught at iteration {result['caught_at_iteration']})" if result["caught_at_iteration"] else ""))
    L.append(f"TERMINATED     : {result['terminated']}")
    return "\n".join(L)


def _main() -> int:
    ap = argparse.ArgumentParser(description="Self-correction engine: miss->catch on a timestomp.")
    ap.add_argument("bodyfile")
    ap.add_argument("memory_source", help=".raw image | dir of cached vol json")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--mft-entry", type=int)
    g.add_argument("--path", help="substring of the target path")
    ap.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS_DEFAULT)
    ap.add_argument("--json", action="store_true", help="emit JSON trace instead of narration")
    ap.add_argument("--trace-out", help="also write the JSON trace here (component #8 log)")
    args = ap.parse_args()

    t = _lookup_times(args.bodyfile, args.mft_entry, args.path)
    procs = get_process_list(args.memory_source)
    result = investigate(t["path"], t["si"], t["fn"], t["entry"], procs, args.max_iterations)

    if args.trace_out:
        with open(args.trace_out, "w") as fh:
            json.dump(result, fh, indent=2)
    print(json.dumps(result, indent=2) if args.json else _narrate(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
