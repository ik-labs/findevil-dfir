"""Tests for the scoring harness — TP / FN / FP and the iter1-vs-final catch logic.

Run: python3 scoring/tests/test_scoring.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from score import score  # noqa: E402

KEY = {"injections": [{"inj_id": "INJ-01", "type": "timestomp", "mft_entry": 104046,
                       "expected_verdict": "confirmed_timestomp"}]}


def _finding(entry, final, curve):
    return {"target": f"x/{entry}", "mft_entry": entry, "final_verdict": final,
            "caught_at_iteration": next((c["iteration"] for c in curve if c["verdict"] == final), None),
            "accuracy_curve": curve}


def _curve(*verdicts):
    return [{"iteration": i + 1, "verdict": v} for i, v in enumerate(verdicts)]


def test_true_positive_caught_at_final_not_iter1():
    run = {"findings": [_finding(104046, "confirmed_timestomp",
                                 _curve("benign", "suspected_timestomp", "confirmed_timestomp"))]}
    m = score(run, KEY)
    assert m["totals"]["catch_at_final"] == 1
    assert m["totals"]["catch_at_iter1"] == 0
    assert m["totals"]["false_negatives"] == 0 and m["totals"]["false_positives"] == 0
    assert m["per_injection"][0]["result"] == "TP"
    assert m["per_injection"][0]["caught_at_iteration"] == 3


def test_false_negative_when_never_confirmed():
    run = {"findings": [_finding(104046, "no_execution", _curve("benign", "suspected_timestomp", "no_execution"))]}
    m = score(run, KEY)
    assert m["totals"]["catch_at_final"] == 0
    assert m["totals"]["false_negatives"] == 1
    assert m["per_injection"][0]["result"] == "FN"


def test_false_positive_on_non_injected_confirmed():
    run = {"findings": [
        _finding(104046, "confirmed_timestomp", _curve("benign", "suspected_timestomp", "confirmed_timestomp")),
        _finding(999999, "confirmed_timestomp", _curve("benign", "suspected_timestomp", "confirmed_timestomp")),
    ]}
    m = score(run, KEY)
    assert m["totals"]["false_positives"] == 1
    assert "x/999999" in m["false_positive_targets"]


def test_iter1_catch_counts_when_expected_present_at_iter1():
    run = {"findings": [_finding(104046, "confirmed_timestomp", _curve("confirmed_timestomp"))]}
    m = score(run, KEY)
    assert m["totals"]["catch_at_iter1"] == 1
    assert m["totals"]["iter1_catch_rate"] == 1.0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} passed")
