#!/usr/bin/env python3
"""
realcase.py — read-only extractors for two real-case artifact classes used in the native
ROCBA hunt: removable-media (USB) history and remote-access (RDP) sessions.

Like memory.py, these read PRE-EXTRACTED structured JSON (usb_devices.json / rdp_sessions.json
produced by gen_realcase.py from the read-only mounted evidence). No raw hive/evtx parsing and
no shell happen here — the MCP tool surface stays purely declarative and read-only.
"""
from __future__ import annotations

import json
import os

USB_FILE = "usb_devices.json"
RDP_FILE = "rdp_sessions.json"
WEB_FILE = "web_activity.json"
EXEC_FILE = "program_execution.json"


def _load(structured: str, name: str) -> dict:
    try:
        with open(os.path.join(structured, name)) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def get_usb_devices(structured: str) -> dict:
    """Removable-media (USBSTOR) history: each device's serial, friendly name, first install,
    last arrival/removal, and mapped drive letter. Relevant to physical/redirected exfil."""
    obj = _load(structured, USB_FILE)
    devices = obj.get("devices", [])
    return {
        "count": len(devices),
        "source": obj.get("source"),
        "devices": devices,
    }


def get_remote_access(structured: str) -> dict:
    """Remote-access picture from the Terminal Services + Security logs: RDP logon/reconnect
    sessions (local vs remote), the remote source IPs, any OUTBOUND RDP (pivots), and a summary
    of failed-logon brute force. The remote source IPs are the key attribution IOCs."""
    obj = _load(structured, RDP_FILE)
    sessions = obj.get("sessions", [])
    remote = [s for s in sessions if s.get("remote")]
    return {
        "session_count": len(sessions),
        "remote_session_count": len(remote),
        "remote_source_ips": obj.get("remote_source_ips", []),
        "sessions": sessions,
        "outbound_rdp": obj.get("outbound_rdp", []),
        "bruteforce": obj.get("bruteforce", {}),
        "source": obj.get("source"),
    }


def get_web_activity(structured: str) -> dict:
    """Browser download history (Microsoft Edge): each file's source URL, save path, time and
    size, with an `exfil` flag for downloads written to removable drives or pulled from corporate
    SharePoint/OneDrive or known cloud-sync installers. Key channel for data theft (T1567/T1052)."""
    obj = _load(structured, WEB_FILE)
    downloads = obj.get("downloads", [])
    return {
        "download_count": len(downloads),
        "exfil_count": obj.get("exfil_count", sum(1 for d in downloads if d.get("exfil"))),
        "downloads": downloads,
        "source": obj.get("source"),
    }


def get_program_execution(structured: str) -> dict:
    """Notable program-execution evidence from the NTUSER UserAssist key: program name, run count
    and last-run time. Surfaces exfil tooling (cloud sync clients), interactive shells, and
    anti-forensics utilities the user actually ran."""
    obj = _load(structured, EXEC_FILE)
    execs = obj.get("executions", [])
    return {
        "execution_count": len(execs),
        "executions": execs,
        "source": obj.get("source"),
    }


if __name__ == "__main__":  # quick manual check
    import sys
    st = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/cases/rocba/output/structured")
    print(json.dumps({"usb": get_usb_devices(st)["count"],
                      "remote": get_remote_access(st)["remote_source_ips"]}, indent=2))
