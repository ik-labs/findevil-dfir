#!/usr/bin/env python3
"""
score.py — the SEPARATE scoring harness. Reads a run output (score-blind system findings) and
the ground-truth key, and computes the accuracy numbers: per-type catch rate at iteration 1 vs
final, false negatives, false positives. This is the only component that reads the key.

A run never sees the key; the key is read here, after the fact. That separation is what makes
the accuracy numbers meaningful (no answer leakage to the model).

Definitions:
  TP  injected contradiction reached its expected verdict (e.g. confirmed_timestomp).
  FN  injected contradiction never reached its expected verdict.
  FP  a NON-injected target reached a "confirmed" verdict (a benign file falsely confirmed).
  catch@iter1   the expected verdict was already present at iteration 1 (one-shot would catch).
  catch@final   the expected verdict was reached by the final iteration (engine catches).
"""

from __future__ import annotations

import argparse
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
# Verdicts that assert "this is evil" — used for false-positive detection (a confirmed verdict
# on a target NOT in the key is an FP). Extended per contradiction type as breadth grows.
CONFIRMED_VERDICTS = {"confirmed_timestomp", "confirmed_masquerade", "masquerade"}


def _earliest_iter(curve: list[dict], expected: str) -> int | None:
    for step in curve:
        if step["verdict"] == expected:
            return step["iteration"]
    return None


def score(run: dict, key: dict) -> dict:
    injections = key["injections"]
    by_entry = {str(f["mft_entry"]): f for f in run["findings"]}
    key_entries = {str(i["mft_entry"]) for i in injections}

    per_injection, types = [], {}
    catch_final = catch_iter1 = 0
    for inj in injections:
        entry = str(inj["mft_entry"])
        expected = inj["expected_verdict"]
        f = by_entry.get(entry)
        first = _earliest_iter(f["accuracy_curve"], expected) if f else None
        final_ok = bool(f and f["final_verdict"] == expected)
        iter1_ok = first == 1
        catch_final += int(final_ok)
        catch_iter1 += int(iter1_ok)
        t = types.setdefault(inj["type"], {"n": 0, "final": 0, "iter1": 0})
        t["n"] += 1
        t["final"] += int(final_ok)
        t["iter1"] += int(iter1_ok)
        per_injection.append({
            "inj_id": inj["inj_id"], "type": inj["type"], "mft_entry": entry,
            "expected_verdict": expected,
            "detected_final": final_ok,
            "caught_at_iteration": first,
            "result": "TP" if final_ok else "FN",
        })

    # false positives: confirmed verdicts on targets NOT in the key
    fps = [f for f in run["findings"]
           if f["final_verdict"] in CONFIRMED_VERDICTS and str(f["mft_entry"]) not in key_entries]

    n = len(injections)
    return {
        "totals": {
            "injections": n,
            "catch_at_iter1": catch_iter1,
            "catch_at_final": catch_final,
            "false_negatives": n - catch_final,
            "false_positives": len(fps),
            "iter1_catch_rate": round(catch_iter1 / n, 3) if n else 0.0,
            "final_catch_rate": round(catch_final / n, 3) if n else 0.0,
        },
        "by_type": {k: {**v, "iter1_rate": round(v["iter1"] / v["n"], 3),
                        "final_rate": round(v["final"] / v["n"], 3)} for k, v in types.items()},
        "per_injection": per_injection,
        "false_positive_targets": [f["target"] for f in fps],
    }


def _report(m: dict) -> str:
    t = m["totals"]
    L = ["=== ACCURACY REPORT (scored vs ground-truth key) ===", ""]
    L.append(f"Injections: {t['injections']}   "
             f"catch@iter1: {t['catch_at_iter1']} ({t['iter1_catch_rate']*100:.0f}%)   "
             f"catch@final: {t['catch_at_final']} ({t['final_catch_rate']*100:.0f}%)")
    L.append(f"False negatives: {t['false_negatives']}   False positives: {t['false_positives']}")
    L.append("")
    L.append("per injection:")
    for p in m["per_injection"]:
        L.append(f"  {p['inj_id']} [{p['type']}] entry {p['mft_entry']}: {p['result']}  "
                 f"(expected {p['expected_verdict']}, caught@iter {p['caught_at_iteration']})")
    if m["false_positive_targets"]:
        L.append("")
        L.append("FALSE POSITIVES:")
        for fp in m["false_positive_targets"]:
            L.append(f"  {fp}")
    L.append("")
    L.append("accuracy matrix rows (for 03_CONTRADICTION_TAXONOMY.md):")
    for ty, v in m["by_type"].items():
        L.append(f"  | {ty} | iter1 {v['iter1']}/{v['n']} | final {v['final']}/{v['n']} |")
    return "\n".join(L)


def _main() -> int:
    ap = argparse.ArgumentParser(description="Grade a run output against the ground-truth key.")
    ap.add_argument("run_output")
    ap.add_argument("--groundtruth", default=os.path.join(_HERE, "groundtruth.json"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write metrics JSON here")
    args = ap.parse_args()
    run = json.load(open(args.run_output))
    key = json.load(open(args.groundtruth))
    metrics = score(run, key)
    if args.out:
        json.dump(metrics, open(args.out, "w"), indent=2)
    print(json.dumps(metrics, indent=2) if args.json else _report(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
