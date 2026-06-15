# Accuracy Report

> SANS Find Evil! submission component #7. **Honesty over perfection:** this report states what
> was measured, what was suppressed and why, and which real-case findings are tool-confirmed vs
> analyst-inferred.

## 1. Methodology (anti-leakage by design)

Detection accuracy is measured against **planted ground truth** — two contradictions injected at
known byte offsets — so there is an objective answer key:

- `scoring/run_case.py` is **key-blind**: it runs the engine over the evidence and never reads the key.
- `scoring/score.py` is the **only** component that reads `scoring/groundtruth.json`, and only
  *after* the run. The agent never sees the key during execution.

Reproduce: `python3 demo_selfcorrection.py` (engine + blind score) and
`python3 agent/agent.py` (autonomous agent).

## 2. Headline results (planted ground truth)

| Metric | Value |
|---|---|
| catch @ iteration 1 (one-shot) | **0 / 2 (0%)** |
| catch @ final (after self-correction) | **2 / 2 (100%)** |
| False positives | **0** |
| False negatives | **0** |
| Candidates scanned | **35** |

| Injection | Type | Caught @ | Confirmed by |
|---|---|---|---|
| INJ-01 `OneDrive.exe` | Timestomp (T1070.006) | iter 3 | disk `$SI` vs `$FN` (591.79d) **+ memory** PID 9648 |
| INJ-02 `svchost.exe` | Masquerade (T1036) | iter 2 | name vs canonical path (not in `System32`) |

A one-shot look scores 0% (the forged fields fool it); cross-source self-correction reaches 100%.

## 3. False positives we found and suppressed during testing

A naive `$SI < $FN` check produced **157,536 raw "hits."** Almost all were benign. We identified
and suppressed these false-positive classes (this is where most of the engineering went):

- **Null-`$SI` cache files** (`$SI` epoch `1980-01-01`) — excluded.
- **Installer clusters** — many files sharing one `$SI` from a single extraction; collapsed via a
  cluster threshold instead of being reported individually.
- **Vendor build-before-install gaps** — e.g. a legitimate Adobe service (`armsvc.exe`) was *almost*
  flagged (build date precedes install). We tightened "confirmed" to require a **large backdate
  (≥365d) OR a user-writable path**, which removed it.
- **Masquerade native-process noise** — system processes whose command lines use `%systemroot%` or a
  bare basename produced ~6 false hits; fixed with path canonicalization and skipping path-less entries.

Result after suppression: **2 high-confidence timestomp candidates, 1 masquerade — 0 false positives.**

## 4. Confirmed vs inferred (the engine distinguishes them)

- **Confirmed** requires cross-source corroboration (e.g. disk backdating **and** the file running in
  memory) or an implausible backdate on a user-writable path.
- Single-source signals are reported as **suspected / inferred** (`running_vendor_pattern`,
  `basename_match_only`, …), never as confirmed. The masquerade binary is reported as a
  **disk-resident** finding precisely because it was **not** seen executing — we do not claim execution.

## 5. Real-case findings: tool-confirmed vs analyst-inferred

**Tool-confirmed** (each traceable to a specific artifact via the read-only MCP tools + audit log):

| Finding | Artifact |
|---|---|
| Remote RDP from `52.249.198.56` | TerminalServices-LocalSessionManager EID 24/25 |
| Outbound RDP pivot to `172.16.6.18` | TerminalServices-RDPClient EID 1102 |
| 8 USB devices (serials, drive letters, times) | SYSTEM hive USBSTOR / MountedDevices |
| SharePoint→`F:` download of a colleague's PDF | Edge History `downloads` |
| `GoogleDriveFSSetup.exe` run from USB, `cmd.exe` | NTUSER UserAssist |
| 60 RDP brute-force failures | Security log 4625 |

**Analyst-inferred (explicitly NOT claimed as automated tool findings):**

- **SDelete = anti-forensics intent** — the binary's presence/download is observed, but "used to
  destroy evidence" is an inference.
- **Attribution (insider vs. external actor)** — the evidence shows activity under `fredr` from a
  remote IP; *who* was at the keyboard is not determinable from these artifacts alone.
- **Personal accounts** (`fred.rocba@gmail.com` / `@outlook.com`) — corroborated by hand, not a tool.
- The **brute-force burst** is flagged as likely **opportunistic internet noise** (no matching
  successful logon), not over-attributed to the main intrusion.

## 6. Hallucination control

The agent can only call read-only getters; it cannot invent artifacts because every claim must come
from a tool result, and every tool call is in the audit log (`output/mcp_audit.log`). In testing the
agent appropriately hedged (e.g. "no explicit file-copy artifacts shown") rather than overstating.
The deterministic engine — not the LLM — is the oracle for the scored numbers, so accuracy does not
depend on model behavior.
