"""Regression tests for the spine join (disk timestomp candidate x memory execution).

Run: python3 extractors/tests/test_spine.py   (or pytest)

Locks in the verdict logic learned on real ROCBA:
  * a backdated executable that RUNS from a user-writable path  -> confirmed_timestomp
  * a legit vendor service (small build<install gap, Program Files) that runs -> NOT confirmed
  * backdated but not running -> no_execution
  * same exe name running from a different path -> basename_match_only
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spine import corroborate  # noqa: E402

# epochs: 2019-01-01=1546300800 ; 2020-09-06=1599383706 ; 2020-10-27=1603768800 ;
#         2020-11-10=1604966400 ; 2020-11-12=1605139200


def cand(path, si, fn, conf="high"):
    from datetime import datetime, timezone
    iso = lambda e: datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"path": path, "confidence": conf, "backdate_days": round((fn - si) / 86400, 2),
            "si_crtime": iso(si), "fn_crtime": iso(fn),
            "provenance": "$MFT entry test"}


def proc(pid, norm_path, start_iso):
    return {"pid": pid, "ppid": 4, "name": norm_path.rsplit("/", 1)[-1], "start": start_iso,
            "exit": "", "path": norm_path, "norm_path": norm_path, "provenance": f"_EPROCESS PID {pid}"}


def test_confirmed_when_running_from_userwritable():
    c = cand("C:/Users/fredr/AppData/Local/Temp/evil.exe", 1546300800, 1604966400)
    p = proc(6666, "users/fredr/appdata/local/temp/evil.exe", "2020-11-12T00:00:00+00:00")
    f = corroborate([c], [p])[0]
    assert f["verdict"] == "confirmed_timestomp", f["verdict"]
    assert f["memory"]["matched_pid"] == 6666
    assert len(f["provenance"]) == 2  # disk + memory


def test_vendor_service_not_confirmed():
    # Adobe armsvc pattern: 50d build<install, Program Files, legitimately running
    c = cand("C:/Program Files (x86)/Common Files/Adobe/ARM/1.0/armsvc.exe", 1599383706, 1603768800)
    p = proc(4472, "program files (x86)/common files/adobe/arm/1.0/armsvc.exe", "2020-11-11T08:13:19+00:00")
    f = corroborate([c], [p])[0]
    assert f["verdict"] == "running_vendor_pattern", f["verdict"]


def test_large_backdate_confirms_even_in_program_files():
    c = cand("C:/Program Files/App/tool.exe", 1546300800, 1604966400)  # ~680d backdate
    p = proc(7777, "program files/app/tool.exe", "2020-11-12T00:00:00+00:00")
    f = corroborate([c], [p])[0]
    assert f["verdict"] == "confirmed_timestomp", f["verdict"]


def test_no_execution_when_not_running():
    c = cand("C:/Users/fredr/AppData/Local/Temp/evil.exe", 1546300800, 1604966400)
    f = corroborate([c], [])[0]
    assert f["verdict"] == "no_execution"
    assert f["memory"] is None


def test_basename_match_only_is_masquerade_signal():
    c = cand("C:/Users/fredr/AppData/Local/Temp/svchost.exe", 1546300800, 1604966400)
    p = proc(900, "windows/system32/svchost.exe", "2020-11-12T00:00:00+00:00")
    f = corroborate([c], [p])[0]
    assert f["verdict"] == "basename_match_only", f["verdict"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} passed")
