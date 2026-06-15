#!/usr/bin/env python3
"""
Memory-side extractors for the Find Evil! agent — the other half of the spine.

get_process_list()  -> running processes with start/exit times AND the on-disk path each
                       was launched from (so findings can be matched to disk artifacts).
get_process_start() -> a single process's start time by PID.

Source of truth = Volatility 3 over the raw memory image:
  * windows.pslist  -> PID, PPID, ImageFileName (basename), CreateTime, ExitTime
  * windows.cmdline -> PID, Args (full command line; first token = the exe path)

pslist alone only gives the 14-char-ish basename, which is too weak to join against a disk
path (basenames collide — every svchost.exe looks alike). cmdline gives the real launch path,
which is what masquerade/timestomp detection needs. We normalise paths (lowercase, '\\'->'/' ,
drop a leading drive/`\??\`/`\Device\...`) so memory paths and TSK disk paths compare cleanly.

Each extractor can read pre-rendered Vol JSON (fast, for the agent/tests) or run Volatility
live against a .raw image. Every record carries provenance (_EPROCESS PID) for the audit trail.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, asdict

VOL_BIN = os.environ.get("VOL_BIN", "vol")

_DRIVE = re.compile(r"^[a-z]:")
_DEVICE = re.compile(r"^(\\\?\?\\|\\device\\harddiskvolume\d+\\?|\\systemroot\\)", re.I)


def normalize_path(p: str) -> str:
    """Lowercase, backslashes->slashes, strip drive/device prefix -> a comparable tail.

    'C:\\Users\\fredr\\evil.exe' and '\\Device\\HarddiskVolume2\\Users\\fredr\\evil.exe' and
    'C:/Users/fredr/evil.exe' all reduce to 'users/fredr/evil.exe'.
    """
    if not p:
        return ""
    s = p.strip().strip('"').replace("\\", "/").lower()
    s = re.sub(r"^\?\?/", "", s)
    s = re.sub(r"^[a-z]:", "", s)
    s = re.sub(r"^/device/harddiskvolume\d+", "", s)
    # native/kernel paths: \SystemRoot\, %SystemRoot%, %windir% all mean C:\Windows
    s = re.sub(r"^/?%?systemroot%?", "/windows", s)
    s = re.sub(r"^/?%?windir%?", "/windows", s)
    return s.lstrip("/")


def basename(p: str) -> str:
    return normalize_path(p).rsplit("/", 1)[-1]


def _vol_json(image: str, plugin: str) -> list:
    out = subprocess.run([VOL_BIN, "-r", "json", "-f", image, plugin],
                         capture_output=True, text=True)
    return json.loads(out.stdout or "[]")


def _load(source: str, plugin: str, cache_dir: str | None) -> list:
    """Return Vol records for `plugin`. `source` is a .raw image (run live) or a dir/json file."""
    if os.path.isdir(source):
        path = os.path.join(source, f"{plugin.split('.')[-1]}.json")
        with open(path) as fh:
            return json.load(fh)
    if source.endswith(".json"):
        with open(source) as fh:
            return json.load(fh)
    # a raw image: optionally cache the render
    recs = _vol_json(source, plugin)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        with open(os.path.join(cache_dir, f"{plugin.split('.')[-1]}.json"), "w") as fh:
            json.dump(recs, fh)
    return recs


def _flatten(recs: list) -> list[dict]:
    """pslist/pstree JSON can nest children under __children — flatten to a flat list."""
    flat = []
    stack = list(recs)
    while stack:
        r = stack.pop()
        if isinstance(r, dict):
            kids = r.get("__children") or []
            stack.extend(kids)
            flat.append(r)
    return flat


def _exe_path_from_args(args: str | None) -> str:
    """First token of a command line is the exe path (handle quotes / trailing switches)."""
    if not args:
        return ""
    args = args.strip()
    if args.startswith('"'):
        end = args.find('"', 1)
        return args[1:end] if end != -1 else args[1:]
    try:
        toks = shlex.split(args, posix=False)
        return toks[0].strip('"') if toks else args.split()[0]
    except ValueError:
        return args.split()[0]


@dataclass
class Process:
    pid: int
    ppid: int
    name: str            # ImageFileName (basename)
    start: str           # CreateTime (ISO, as Vol renders it) or ""
    exit: str            # ExitTime or ""
    path: str            # full launch path from cmdline (raw)
    norm_path: str       # normalized tail for joining against disk paths
    provenance: str      # _EPROCESS ref for the audit trail


def get_process_list(source: str, cache_dir: str | None = None) -> list[dict]:
    """Enriched running-process list: {pid, ppid, name, start, exit, path, norm_path}."""
    ps = _flatten(_load(source, "windows.pslist", cache_dir))
    try:
        cmd = _load(source, "windows.cmdline", cache_dir)
    except (FileNotFoundError, json.JSONDecodeError):
        cmd = []
    pid_to_path = {}
    for c in cmd:
        if isinstance(c, dict) and c.get("PID") is not None:
            pid_to_path[c["PID"]] = _exe_path_from_args(c.get("Args"))

    procs: list[Process] = []
    for r in ps:
        if not isinstance(r, dict) or r.get("PID") is None:
            continue
        pid = r["PID"]
        path = pid_to_path.get(pid, "")
        procs.append(Process(
            pid=pid,
            ppid=r.get("PPID") or 0,
            name=r.get("ImageFileName") or "",
            start=(r.get("CreateTime") or "") if r.get("CreateTime") not in (None, "N/A") else "",
            exit=(r.get("ExitTime") or "") if r.get("ExitTime") not in (None, "N/A") else "",
            path=path,
            norm_path=normalize_path(path),
            provenance=f"_EPROCESS PID {pid} (windows.pslist + windows.cmdline)",
        ))
    return [asdict(p) for p in procs]


def get_process_start(source: str, pid: int, cache_dir: str | None = None) -> str | None:
    for p in get_process_list(source, cache_dir):
        if p["pid"] == pid:
            return p["start"] or None
    return None


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="List processes (pid,name,start,path) from memory.")
    ap.add_argument("source", help=".raw image | dir of cached vol json | a pslist.json")
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--with-path-only", action="store_true", help="only procs that resolved a launch path")
    args = ap.parse_args()
    procs = get_process_list(args.source, args.cache_dir)
    if args.with_path_only:
        procs = [p for p in procs if p["norm_path"]]
    print(json.dumps({"count": len(procs), "processes": procs}, indent=2))
