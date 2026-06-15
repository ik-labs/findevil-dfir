#!/usr/bin/env python3
"""
tools.py — the typed, read-only forensic functions the MCP server exposes.

These wrap the validated extractors (timestomp / memory / spine) and add the two things the
architecture promises:
  1. STRUCTURED output — raw tool dumps are parsed to small typed results (no context-window
     overload); the agent never receives a 72M-token timeline.
  2. An AUDIT line per call — timestamp + tool + args + the artifact refs returned — so every
     finding the agent reports traces back to a specific tool execution (the audit trail).

What is DELIBERATELY ABSENT is the whole point (submission component #6): there is no
run_shell / exec / write / delete function here. The agent calls these getters or nothing.
Evidence cannot be modified because no tool can modify it — architecturally, not by prompt.
All data sources are read-only (the original e01 is chmod a-w; these are parsed renders of it).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "extractors"))

import timestomp as _ts            # noqa: E402
import memory as _mem              # noqa: E402
import spine as _spine             # noqa: E402
import masquerade as _mq           # noqa: E402
import realcase as _real           # noqa: E402

CASE = os.environ.get("FINDEVIL_CASE", os.path.expanduser("~/cases/rocba"))
BODYFILE = os.environ.get("FINDEVIL_BODYFILE", os.path.join(CASE, "work/injected/rocba-INJ-01.body"))
STRUCTURED = os.environ.get("FINDEVIL_STRUCTURED", os.path.join(CASE, "output/structured"))
NETSCAN = os.environ.get("FINDEVIL_NETSCAN", os.path.join(STRUCTURED, "netscan.json"))
AUDIT_LOG = os.environ.get("FINDEVIL_AUDIT", os.path.join(CASE, "output/mcp_audit.log"))


def _audit(tool: str, args: dict, artifacts: list[str], n: int) -> None:
    line = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "tool": tool, "args": args, "results": n, "artifacts": artifacts[:25]}
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    with open(AUDIT_LOG, "a") as fh:
        fh.write(json.dumps(line) + "\n")


# ── disk ──────────────────────────────────────────────────────────────────────

def get_mft_timestamps(path_substring: str) -> dict:
    """Return $SI vs $FN creation times for files matching `path_substring` (from $MFT).

    The disagreement between $SI (forgeable) and $FN (truth) is the timestomp signal.
    """
    entries = _ts.parse_bodyfile(BODYFILE)
    hits = []
    needle = path_substring.lower()
    for entry, rec in entries.items():
        if rec["path"] and needle in rec["path"].lower() and rec["si"] and rec["fn_crtime"] is not None:
            hits.append({
                "path": rec["path"], "mft_entry": entry,
                "si_creation": _ts._iso(rec["si"]["crtime"]),
                "fn_creation": _ts._iso(rec["fn_crtime"]),
                "si_modified": _ts._iso(rec["si"]["mtime"]),
                "provenance": f"$MFT entry {entry} (TSK fls -r -m bodyfile)",
            })
    hits = hits[:200]
    _audit("get_mft_timestamps", {"path_substring": path_substring},
           [h["provenance"] for h in hits], len(hits))
    return {"count": len(hits), "files": hits}


def get_timestomp_candidates(min_confidence: str = "high") -> dict:
    """Disk-side timestomp candidates ($SI backdated vs $FN), false-positive-filtered."""
    res = _ts.get_timestomp_candidates(BODYFILE)
    keep = {"high": ["high"], "medium": ["high", "medium"], "all": ["high", "medium", "low"]}.get(min_confidence, ["high"])
    cands = [c for c in res["candidates"] if c["confidence"] in keep]
    _audit("get_timestomp_candidates", {"min_confidence": min_confidence},
           [c["provenance"] for c in cands], len(cands))
    return {"summary": res["summary"], "candidates": cands}


# ── memory ────────────────────────────────────────────────────────────────────

def get_process_list() -> dict:
    """Running processes from memory: pid, ppid, name, start, exit, launch path."""
    procs = _mem.get_process_list(STRUCTURED)
    _audit("get_process_list", {}, [p["provenance"] for p in procs], len(procs))
    return {"count": len(procs), "processes": procs}


def get_process_start(pid: int) -> dict:
    """Start time of a single process by PID (from _EPROCESS / windows.pslist)."""
    start = _mem.get_process_start(STRUCTURED, pid)
    _audit("get_process_start", {"pid": pid}, [f"_EPROCESS PID {pid}"], 1 if start else 0)
    return {"pid": pid, "start": start, "provenance": f"_EPROCESS PID {pid} (windows.pslist)"}


def get_network_connections() -> dict:
    """Network connections from memory (windows.netscan), trimmed to the essentials."""
    try:
        with open(NETSCAN) as fh:
            raw = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        raw = []
    conns = []
    for r in raw:
        if not isinstance(r, dict) or r.get("PID") is None:
            continue
        conns.append({"proto": r.get("Proto"), "local": f"{r.get('LocalAddr')}:{r.get('LocalPort')}",
                      "foreign": f"{r.get('ForeignAddr')}:{r.get('ForeignPort')}",
                      "state": r.get("State"), "pid": r.get("PID"), "owner": r.get("Owner"),
                      "provenance": f"_TCP/_UDP endpoint, PID {r.get('PID')} (windows.netscan)"})
    _audit("get_network_connections", {}, [c["provenance"] for c in conns], len(conns))
    return {"count": len(conns), "connections": conns}


# ── cross-source (the headline) ───────────────────────────────────────────────

def detect_timestomps(min_confidence: str = "high") -> dict:
    """Full cross-source timestomp detection: disk $SI/$FN candidates corroborated against
    memory process execution. Returns ranked findings, each with disk + memory provenance.
    """
    res = _spine.detect_timestomps(BODYFILE, STRUCTURED, min_confidence=min_confidence)
    arts = []
    for f in res["findings"]:
        arts.extend(f.get("provenance", []))
    _audit("detect_timestomps", {"min_confidence": min_confidence}, arts, len(res["findings"]))
    return res


def detect_masquerade() -> dict:
    """Detect system-binary masquerade (T1036): files/processes named like a Windows system
    binary but living outside the canonical System32/SysWOW64 location. Cross-references disk
    and memory; returns ranked findings with provenance.
    """
    res = _mq.detect_masquerade(BODYFILE, STRUCTURED)
    arts = []
    for f in res["findings"]:
        arts.extend(f.get("provenance", []))
    _audit("detect_masquerade", {}, arts, len(res["findings"]))
    return res


# ── real-case intel (removable media + remote access) ─────────────────────────

def get_usb_devices() -> dict:
    """Removable-media (USBSTOR) history from the SYSTEM hive: serial, friendly name, first
    install, last arrival/removal, drive letter. Relevant to data exfiltration to USB."""
    res = _real.get_usb_devices(STRUCTURED)
    _audit("get_usb_devices", {}, [d.get("provenance", "") for d in res["devices"]], res["count"])
    return res


def get_remote_access() -> dict:
    """Remote-access picture from Terminal Services + Security logs: RDP sessions (local vs
    remote), remote source IPs (attribution IOCs), OUTBOUND RDP pivots, and brute-force summary."""
    res = _real.get_remote_access(STRUCTURED)
    arts = [s.get("provenance", "") for s in res["sessions"]] + \
           [o.get("provenance", "") for o in res["outbound_rdp"]]
    _audit("get_remote_access", {}, arts, res["session_count"])
    return res


def get_web_activity() -> dict:
    """Browser download history (Edge): source URL, save path, time, size, with an exfil flag for
    removable-drive targets, corporate SharePoint/OneDrive sources, and cloud-sync installers."""
    res = _real.get_web_activity(STRUCTURED)
    _audit("get_web_activity", {}, [d.get("provenance", "") for d in res["downloads"]], res["download_count"])
    return res


def get_program_execution() -> dict:
    """Notable program-execution evidence (NTUSER UserAssist): name, run count, last-run time —
    exfil tooling, shells, and anti-forensics utilities the user ran."""
    res = _real.get_program_execution(STRUCTURED)
    _audit("get_program_execution", {}, [e.get("provenance", "") for e in res["executions"]], res["execution_count"])
    return res


# Registry of the ONLY callable tools. Used by server.py and the no-write-capability test.
READ_ONLY_TOOLS = {
    "get_mft_timestamps": get_mft_timestamps,
    "get_timestomp_candidates": get_timestomp_candidates,
    "get_process_list": get_process_list,
    "get_process_start": get_process_start,
    "get_network_connections": get_network_connections,
    "detect_timestomps": detect_timestomps,
    "detect_masquerade": detect_masquerade,
    "get_usb_devices": get_usb_devices,
    "get_remote_access": get_remote_access,
    "get_web_activity": get_web_activity,
    "get_program_execution": get_program_execution,
}
