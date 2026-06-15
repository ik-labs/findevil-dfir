"""Regression tests for get_timestomp_candidates.

Run: python3 -m pytest extractors/tests/ -q   (or: python3 extractors/tests/test_timestomp.py)

These use synthetic bodyfiles so they run anywhere — no evidence needed. They lock in the
two behaviours that matter: (1) FIRE on a real backdated executable, (2) SUPPRESS the
false-positive classes we found on ROCBA (null-$SI cache, shared-$SI installer clusters).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from timestomp import get_timestomp_candidates  # noqa: E402

# epochs: 2019-01-01=1546300800, 2020-11-12=1605139200, 1970≈0, 2002-02-01=1012608122
SI, FN = 7, 10  # unused doc of field positions


def _body(lines):
    fh = tempfile.NamedTemporaryFile("w", suffix=".body", delete=False)
    fh.write("\n".join(lines) + "\n")
    fh.close()
    return fh.name


def _pair(path, mft, si_cr, fn_cr, size=50000):
    """One $SI line + one $FN line for the same MFT entry (times = a|m|c|cr)."""
    return [
        f"0|{path}|{mft}-128-1|r/rrwxrwxrwx|0|0|{size}|{fn_cr}|{fn_cr}|{fn_cr}|{si_cr}",
        f"0|{path} ($FILE_NAME)|{mft}-48-2|r/rrwxrwxrwx|0|0|{size}|{fn_cr}|{fn_cr}|{fn_cr}|{fn_cr}",
    ]


def test_fires_on_real_timestomp():
    bf = _body(_pair("C:/Users/fredr/AppData/Local/Temp/evil.exe", "999999", 1546300800, 1605139200))
    r = get_timestomp_candidates(bf)
    assert r["summary"]["by_confidence"]["high"] == 1
    c = r["candidates"][0]
    assert c["confidence"] == "high" and c["path"].endswith("evil.exe")
    assert c["backdate_days"] > 600 and "entry 999999" in c["provenance"]


def test_ignores_equal_si_fn():
    bf = _body(_pair("C:/Windows/System32/legit.dll", "111", 1605139200, 1605139200))
    r = get_timestomp_candidates(bf)
    assert r["summary"]["returned"] == 0


def test_suppresses_null_si_cache():
    # app cache with $SI=epoch0 — the 157k-FP class on ROCBA
    bf = _body(_pair("C:/Users/fredr/AppData/Local/Google/Chrome/User Data/x/cache_0", "222", 0, 1605139200))
    r = get_timestomp_candidates(bf)
    assert r["summary"]["by_confidence"]["null_si"] == 1
    assert r["summary"]["returned"] == 0


def test_suppresses_installer_cluster():
    # many Program Files DLLs sharing the exact same old $SI second = installer extraction
    lines = []
    for i in range(20):
        lines += _pair(f"C:/Program Files/Common Files/VSTO/lib{i}.dll", f"30{i:03d}", 1012608122, 1605139200)
    r = get_timestomp_candidates(_body(lines))
    assert r["summary"]["by_confidence"]["installer"] == 20
    assert r["summary"]["by_confidence"]["high"] == 0
    assert r["summary"]["returned"] == 0


def test_program_files_single_is_medium_not_high():
    # one backdated exe in Program Files (not user-writable, not clustered) -> MEDIUM
    bf = _body(_pair("C:/Program Files/App/tool.exe", "444", 1546300800, 1605139200))
    r = get_timestomp_candidates(bf)
    assert r["summary"]["by_confidence"]["medium"] == 1
    assert r["summary"]["by_confidence"]["high"] == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} passed")
