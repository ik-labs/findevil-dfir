#!/usr/bin/env python3
"""
server.py — the Find Evil! Custom MCP Server (the architectural guardrail).

Exposes the forensic functions in tools.py as MCP tools over stdio, so a Claude Code agent
calls TYPED, READ-ONLY operations instead of a raw shell. This is the submission's headline:
the evidence-integrity guarantee is ARCHITECTURAL, not a prompt request.

  * Every tool is a getter returning structured data; raw tool output is parsed first.
  * Every tool call is written to an audit log (timestamp + tool + artifact refs).
  * There is NO run_shell / exec / write / delete tool. The agent physically cannot run a
    destructive command or write to evidence — the capability does not exist in the server.

Register with Claude Code (example .mcp.json):
  { "mcpServers": { "findevil": { "command": "python3",
      "args": ["/home/ubuntu/cases/rocba/findevil/mcp_server/server.py"] } } }

Run standalone (stdio): python3 server.py
"""

from mcp.server.fastmcp import FastMCP

import tools

mcp = FastMCP("findevil-dfir")


@mcp.tool()
def get_mft_timestamps(path_substring: str) -> dict:
    """Get $STANDARD_INFORMATION vs $FILE_NAME creation times for files whose path contains
    `path_substring`. A large $SI-vs-$FN disagreement is the timestomp signal (T1070.006)."""
    return tools.get_mft_timestamps(path_substring)


@mcp.tool()
def get_timestomp_candidates(min_confidence: str = "high") -> dict:
    """List disk-side timestomp candidates (files whose $SI creation is backdated vs $FN),
    already filtered for the known false-positive classes. min_confidence: high|medium|all."""
    return tools.get_timestomp_candidates(min_confidence)


@mcp.tool()
def get_process_list() -> dict:
    """List running processes from the memory image: pid, ppid, name, start/exit time, and the
    on-disk path each was launched from."""
    return tools.get_process_list()


@mcp.tool()
def get_process_start(pid: int) -> dict:
    """Get the start time of one process by PID (from its _EPROCESS / windows.pslist)."""
    return tools.get_process_start(pid)


@mcp.tool()
def get_network_connections() -> dict:
    """List network connections recovered from memory (windows.netscan): proto, local/foreign
    endpoints, state, owning PID."""
    return tools.get_network_connections()


@mcp.tool()
def detect_timestomps(min_confidence: str = "high") -> dict:
    """Cross-source timestomp detection: disk $SI/$FN candidates corroborated against live
    process execution in memory. Returns ranked findings with disk + memory provenance."""
    return tools.detect_timestomps(min_confidence)


@mcp.tool()
def detect_masquerade() -> dict:
    """Detect system-binary masquerade (T1036): files/processes named like a Windows system
    binary (svchost.exe, lsass.exe, ...) but outside the canonical System32 location."""
    return tools.detect_masquerade()


@mcp.tool()
def get_usb_devices() -> dict:
    """List removable-media (USB) history from the SYSTEM hive: each device's serial, friendly
    name, first-install and last arrival/removal times, and drive letter. Use this to assess
    data exfiltration to removable media (T1052)."""
    return tools.get_usb_devices()


@mcp.tool()
def get_remote_access() -> dict:
    """Summarize remote access from the Terminal Services + Security event logs: RDP logon/
    reconnect sessions (distinguishing LOCAL console vs REMOTE), the remote source IP addresses
    (key attribution IOCs), any OUTBOUND RDP connections (lateral movement/pivot), and a summary
    of failed-logon brute force. Use this to determine whether activity was local or remote."""
    return tools.get_remote_access()


@mcp.tool()
def get_web_activity() -> dict:
    """List browser download history (Microsoft Edge): each file's source URL, save path, time and
    size, with an exfil flag for downloads saved to removable drives, pulled from corporate
    SharePoint/OneDrive, or cloud-sync installers. Use this to find data-exfiltration evidence."""
    return tools.get_web_activity()


@mcp.tool()
def get_program_execution() -> dict:
    """List notable program-execution evidence from the NTUSER UserAssist key: program name, run
    count, and last-run time. Surfaces exfil tooling (cloud sync clients), interactive shells, and
    anti-forensics utilities the user actually ran."""
    return tools.get_program_execution()


if __name__ == "__main__":
    mcp.run()
