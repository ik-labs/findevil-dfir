#!/usr/bin/env python3
"""
masquerade.py — detect system-binary MASQUERADE (MITRE T1036): a file/process named like a
trusted Windows system binary but living outside its canonical location (and/or with a hash
that doesn't match the real one). Name-based trust is the blind spot; name+path+execution
correlation is the catch.

Two sources, cross-referenced:
  * memory  — a process whose ImageFileName is a known system binary but whose launch path is
              NOT the canonical System32/SysWOW64 location. This is unambiguous and high-signal
              (lsass.exe should NEVER run from C:\\Users\\...).
  * disk    — an MFT file whose basename is a known system binary but whose directory is a
              user-writable, non-system location. Filtered hard: legit alternate copies live in
              WinSxS / servicing / DriverStore / Windows.old / prefetch and are excluded.

A disk masquerade that ALSO has a matching running process = confirmed_masquerade (the planted
binary is executing under a trusted name from the wrong place).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memory import get_process_list, normalize_path, basename  # noqa: E402
import timestomp as _ts  # noqa: E402

# Known Windows system binaries and their canonical (normalized) locations. A copy anywhere
# else under a user-writable path is suspicious.
SYSTEM_BINARIES = {
    "svchost.exe": {"windows/system32/svchost.exe", "windows/syswow64/svchost.exe"},
    "lsass.exe": {"windows/system32/lsass.exe"},
    "services.exe": {"windows/system32/services.exe"},
    "csrss.exe": {"windows/system32/csrss.exe"},
    "winlogon.exe": {"windows/system32/winlogon.exe"},
    "wininit.exe": {"windows/system32/wininit.exe"},
    "smss.exe": {"windows/system32/smss.exe"},
    "spoolsv.exe": {"windows/system32/spoolsv.exe"},
    "taskhostw.exe": {"windows/system32/taskhostw.exe"},
    "dllhost.exe": {"windows/system32/dllhost.exe", "windows/syswow64/dllhost.exe"},
    "conhost.exe": {"windows/system32/conhost.exe"},
    "rundll32.exe": {"windows/system32/rundll32.exe", "windows/syswow64/rundll32.exe"},
    "explorer.exe": {"windows/explorer.exe", "windows/syswow64/explorer.exe"},
    "lsaiso.exe": {"windows/system32/lsaiso.exe"},
    "fontdrvhost.exe": {"windows/system32/fontdrvhost.exe"},
}

# Directories that legitimately hold alternate copies of system binaries — never a masquerade.
LEGIT_COPY_DIRS = [
    "winsxs", "/servicing/", "driverstore", "windows.old", "/prefetch/", "$windows.~bt",
    "windows10upgrade", "/catroot", "/sysnative/",
]
# A masquerade really bites when the binary sits where a user/attacker can drop it.
USER_WRITABLE = ["users/", "/appdata", "/temp/", "/tmp/", "programdata", "/public/", "/downloads/"]


def _canonical(name: str, norm_path: str) -> bool:
    return norm_path in SYSTEM_BINARIES.get(name, set())


def scan_memory(processes: list[dict]) -> list[dict]:
    out = []
    for p in processes:
        name = p["name"].lower()
        # need an actual directory to judge location; a bare basename (cmdline gave no path)
        # carries no location info, so we cannot call it a masquerade.
        if name in SYSTEM_BINARIES and "/" in p["norm_path"] and not _canonical(name, p["norm_path"]):
            user = any(u in "/" + p["norm_path"] for u in USER_WRITABLE)
            out.append({"source": "memory", "name": name, "path": p["norm_path"], "pid": p["pid"],
                        "start": p["start"], "confidence": "high" if user else "medium",
                        "expected": sorted(SYSTEM_BINARIES[name]),
                        "provenance": p["provenance"]})
    return out


def scan_disk(bodyfile: str) -> list[dict]:
    entries = _ts.parse_bodyfile(bodyfile)
    out = []
    for entry, rec in entries.items():
        if not rec["path"]:
            continue
        norm = normalize_path(rec["path"])
        name = basename(norm)
        if name not in SYSTEM_BINARIES or _canonical(name, norm):
            continue
        low = "/" + norm
        if any(d in low for d in LEGIT_COPY_DIRS):
            continue
        if not any(u in low for u in USER_WRITABLE):
            continue  # only flag user-writable drops; system-ish paths are too noisy
        out.append({"source": "disk", "name": name, "path": norm, "mft_entry": entry,
                    "confidence": "medium", "expected": sorted(SYSTEM_BINARIES[name]),
                    "provenance": f"$MFT entry {entry} (basename matches system binary, wrong path)"})
    return out


def detect_masquerade(bodyfile: str, memory_source: str) -> dict:
    procs = get_process_list(memory_source)
    mem = scan_memory(procs)
    disk = scan_disk(bodyfile)
    mem_by_path = {m["path"]: m for m in mem}

    findings = []
    for d in disk:
        m = mem_by_path.get(d["path"])
        if m:
            findings.append({**d, "verdict": "confirmed_masquerade", "confidence": "high",
                             "memory": {"pid": m["pid"], "start": m["start"]},
                             "reasoning": f"{d['name']} on disk at non-system path {d['path']} is "
                                          f"EXECUTING (pid {m['pid']}) — masquerading as a system binary.",
                             "provenance": [d["provenance"], m["provenance"]]})
        else:
            findings.append({**d, "verdict": "disk_masquerade",
                             "reasoning": f"{d['name']} present at non-system path {d['path']} "
                                          f"(expected {d['expected']}); not seen running.",
                             "provenance": [d["provenance"]]})
    matched_paths = {d["path"] for d in disk}
    for m in mem:
        if m["path"] in matched_paths:
            continue
        findings.append({**m, "verdict": "running_masquerade",
                         "reasoning": f"{m['name']} (pid {m['pid']}) running from {m['path']}, "
                                      f"not its canonical {m['expected']} — masquerade.",
                         "provenance": [m["provenance"]]})

    order = {"confirmed_masquerade": 0, "running_masquerade": 1, "disk_masquerade": 2}
    findings.sort(key=lambda f: order.get(f["verdict"], 9))
    vc: dict[str, int] = {}
    for f in findings:
        vc[f["verdict"]] = vc.get(f["verdict"], 0) + 1
    return {"summary": {"memory_hits": len(mem), "disk_hits": len(disk), "by_verdict": vc},
            "findings": findings}


def _main() -> int:
    ap = argparse.ArgumentParser(description="Detect system-binary masquerade (T1036).")
    ap.add_argument("bodyfile")
    ap.add_argument("memory_source")
    args = ap.parse_args()
    json.dump(detect_masquerade(args.bodyfile, args.memory_source), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
