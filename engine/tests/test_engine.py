"""Regression tests for the self-correction engine.

Run: python3 engine/tests/test_engine.py   (or pytest)

Locks in the four behaviours that make the accuracy claim honest:
  miss->catch climb, the hard-cap honest miss (no guessing), no false catch on a clean file,
  and disk-only backdating that memory does NOT corroborate.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "extractors"))
from engine import investigate, investigate_masquerade  # noqa: E402

SI_OLD = "2019-03-15T08:00:00Z"      # forged/backdated
FN_REAL = "2020-10-27T02:56:48Z"     # true recent creation
TARGET = "C:/Users/fredr/AppData/Local/Microsoft/OneDrive/OneDrive.exe"


def _proc(pid, norm_path, start):
    return {"pid": pid, "ppid": 4, "name": norm_path.rsplit("/", 1)[-1], "start": start,
            "exit": "", "path": norm_path, "norm_path": norm_path, "provenance": f"_EPROCESS PID {pid}"}


RUNNING = [_proc(9648, "users/fredr/appdata/local/microsoft/onedrive/onedrive.exe", "2020-11-11T08:14:02+00:00")]


def test_miss_to_catch():
    r = investigate(TARGET, SI_OLD, FN_REAL, "104046", RUNNING, max_iterations=5)
    assert r["final_verdict"] == "confirmed_timestomp"
    assert r["caught_at_iteration"] == 3
    assert [c["verdict"] for c in r["accuracy_curve"]] == ["benign", "suspected_timestomp", "confirmed_timestomp"]
    assert r["terminated"] == "resolved"
    # both provenances present on the catching iteration
    assert len(r["trace"][-1]["provenance"]) == 2


def test_hard_cap_is_honest_miss():
    r = investigate(TARGET, SI_OLD, FN_REAL, "104046", RUNNING, max_iterations=1)
    assert r["terminated"] == "max_iterations"
    assert "unresolved" in r["final_verdict"] and "needs human" in r["final_verdict"]
    assert r["iterations_run"] == 1  # no runaway, no guess past the cap


def test_no_false_catch_on_clean_file():
    r = investigate(TARGET, FN_REAL, FN_REAL, "104046", RUNNING, max_iterations=5)
    assert r["final_verdict"] == "benign"
    assert r["terminated"] == "resolved"
    assert r["iterations_run"] == 2  # resolves once $SI==$FN confirmed


def test_disk_only_backdate_not_confirmed_without_execution():
    r = investigate(TARGET, SI_OLD, FN_REAL, "104046", [], max_iterations=5)
    assert r["final_verdict"] == "no_execution"   # backdated but not running -> not escalated
    assert r["caught_at_iteration"] is None


def test_masquerade_name_trust_miss_to_path_catch():
    # iter1 trusts "svchost.exe", iter2 sees the user-dir path -> masquerade
    r = investigate_masquerade("svchost.exe", "C:/Users/fredr/AppData/Local/x/svchost.exe", "104210", [])
    assert r["final_verdict"] == "masquerade"
    assert r["caught_at_iteration"] == 2
    assert [c["verdict"] for c in r["accuracy_curve"]] == ["benign", "masquerade"]


def test_masquerade_confirmed_when_running():
    proc = {"pid": 9, "ppid": 4, "name": "svchost.exe", "start": "2020-11-11T08:14:00+00:00",
            "exit": "", "path": "users/fredr/appdata/local/x/svchost.exe",
            "norm_path": "users/fredr/appdata/local/x/svchost.exe", "provenance": "_EPROCESS PID 9"}
    r = investigate_masquerade("svchost.exe", "C:/Users/fredr/AppData/Local/x/svchost.exe", "104210", [proc])
    assert r["final_verdict"] == "confirmed_masquerade"


def test_masquerade_canonical_path_stays_benign():
    r = investigate_masquerade("svchost.exe", "C:/Windows/System32/svchost.exe", "1", [])
    assert r["final_verdict"] == "benign"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} passed")
