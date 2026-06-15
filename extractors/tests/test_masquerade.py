"""Tests for the masquerade detector (T1036) — name+path correlation, FP suppression.

Run: python3 extractors/tests/test_masquerade.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import masquerade as mq  # noqa: E402


def _proc(pid, name, norm_path):
    return {"pid": pid, "ppid": 4, "name": name, "start": "2020-11-11T08:14:00+00:00",
            "exit": "", "path": norm_path, "norm_path": norm_path, "provenance": f"_EPROCESS PID {pid}"}


def _body(lines):
    fh = tempfile.NamedTemporaryFile("w", suffix=".body", delete=False)
    fh.write("\n".join(lines) + "\n")
    fh.close()
    return fh.name


def _fn_pair(path, mft):
    return [f"0|{path}|{mft}-128-1|r/r|0|0|9|1|1|1|1",
            f"0|{path} ($FILE_NAME)|{mft}-48-2|r/r|0|0|9|1|1|1|1"]


def test_memory_flags_systemproc_from_userpath():
    procs = [_proc(1, "svchost.exe", "users/fredr/appdata/local/x/svchost.exe")]
    hits = mq.scan_memory(procs)
    assert len(hits) == 1 and hits[0]["confidence"] == "high"


def test_memory_ignores_canonical_and_bareword():
    procs = [_proc(1, "svchost.exe", "windows/system32/svchost.exe"),  # canonical
             _proc(2, "csrss.exe", "csrss.exe")]                        # bare name, no dir
    assert mq.scan_memory(procs) == []


def test_disk_flags_systemname_in_userdir():
    bf = _body(_fn_pair("C:/Users/fredr/AppData/Local/Microsoft/OneDrive/svchost.exe", "104210"))
    hits = mq.scan_disk(bf)
    assert len(hits) == 1 and hits[0]["name"] == "svchost.exe"


def test_disk_ignores_winsxs_and_system32_copies():
    bf = _body(_fn_pair("C:/Windows/WinSxS/amd64.../svchost.exe", "1")
               + _fn_pair("C:/Windows/System32/svchost.exe", "2"))
    assert mq.scan_disk(bf) == []


def test_confirmed_when_disk_masquerade_is_running():
    bf = _body(_fn_pair("C:/Users/fredr/AppData/Local/x/svchost.exe", "500"))
    procs = [_proc(9, "svchost.exe", "users/fredr/appdata/local/x/svchost.exe")]
    res = mq.detect_masquerade(bf, _structured(procs))
    assert res["findings"][0]["verdict"] == "confirmed_masquerade"
    assert len(res["findings"][0]["provenance"]) == 2


def _structured(procs):
    """Write a minimal pslist.json+cmdline.json dir so detect_masquerade's get_process_list works."""
    import json
    d = tempfile.mkdtemp()
    json.dump([{"PID": p["pid"], "PPID": 4, "ImageFileName": p["name"],
                "CreateTime": p["start"], "ExitTime": None} for p in procs],
              open(os.path.join(d, "pslist.json"), "w"))
    json.dump([{"PID": p["pid"], "Process": p["name"], "Args": "C:/" + p["norm_path"]} for p in procs],
              open(os.path.join(d, "cmdline.json"), "w"))
    return d


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} passed")
