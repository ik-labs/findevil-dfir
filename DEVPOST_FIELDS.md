# Devpost submission — copy-paste fields

Quick links used below:
- **Repo:** https://github.com/ik-labs/findevil-dfir
- **Live demo:** http://13.235.157.16:8000
- **Accuracy report (full):** https://github.com/ik-labs/findevil-dfir/blob/main/ACCURACY.md
- **Story (full):** https://github.com/ik-labs/findevil-dfir/blob/main/DEVPOST_STORY.md

---

## Project name (≤60)
```
FindEvil: the DFIR agent that can't alter evidence
```

## Elevator pitch (≤200)
```
Autonomous DFIR agent: cross-references disk vs memory to catch tampering, with read-only MCP tools that can't alter evidence. Blind-scored 100%, and reconstructs the real ROCBA intrusion.
```

## Built with (tags)
```
python, mcp, fastmcp, cerebras, gpt-oss-120b, volatility3, sleuthkit, regripper, python-evtx, mftecmd, ewfmount, sift, fastapi, uvicorn, react, tailwindcss, javascript, sqlite, aws-lightsail, ubuntu, linux, systemd
```

## Try it out — links
```
Live demo: http://13.235.157.16:8000
Code (GitHub, MIT): https://github.com/ik-labs/findevil-dfir
```

## "About the project"
Paste the full contents of `DEVPOST_STORY.md`.

## Demo video
```
<paste your YouTube/Vimeo/Youku link here after upload>
```

---

## Include: Evidence Dataset Documentation  ← paste this into the field

**Dataset.** SANS FOR500 **"Fred Rocba" / Stark Research Labs** case — a Windows 10 (build 19041 x64),
single-user host (`SRL-FORGE`) provided as a **disk image (E01)** plus a **memory capture** (acquired
2020-11-16 02:32:38 UTC). Scenario: a new engineer's corporate laptop, an IP-theft investigation, and a
home break-in during the employee's vacation (2020-11-10 → 11-13).

**Source.** SANS FOR500 (Windows Forensic Analysis) training dataset. The course material and raw
evidence are **not redistributed** in our public repo (copyright); only our code and derived,
non-sensitive structured artifacts drive the demo.

**What the agent was tested against.**
- *Real evidence:* the `$MFT` (157,536 entries paired into $SI/$FN), the memory process list
  (Volatility 3 `pslist`/`cmdline`/`netscan`), registry hives (`SYSTEM`/`NTUSER` via RegRipper), event
  logs (Security + TerminalServices via python-evtx), and Edge browser history (SQLite).
- *Planted ground truth (for blind-scored validation):* two adversary-style contradictions injected at
  known byte offsets into a **copy** of the extracted `$MFT` — originals kept read-only.

**Agent findings.**
- *Planted contradictions (scored):* a **timestomped** `OneDrive.exe` ($SI backdated 591.79 days vs
  $FN, contradicted by a live process) and a **masqueraded** `svchost.exe` in a user OneDrive folder.
- *Real intrusion (reconstructed via the read-only tools):* remote **RDP from `52.249.198.56`**, a
  lateral **pivot to `172.16.6.18`**, **8 USB devices**, a colleague's SharePoint document pulled to
  **USB (`F:\Files from SRL system`)**, cloud-sync tooling execution, and a **60-hit RDP brute-force** burst.

Full details: https://github.com/ik-labs/findevil-dfir/blob/main/DEVPOST_STORY.md

---

## Include: Accuracy Report  ← paste this into the field

**Method (anti-leakage).** Accuracy is measured against **planted ground truth** scored by a component
that is the *only* thing allowed to read the answer key, *after* a key-blind run — the agent never sees
the key during execution.

**Results (planted ground truth):**
- catch @ iteration 1 (one-shot): **0/2 (0%)** → catch @ final (after self-correction): **2/2 (100%)**
- **0 false positives, 0 false negatives**, across **35** candidates scanned
- INJ-01 timestomp caught @ iter 3 (disk $SI/$FN **+ memory**); INJ-02 masquerade caught @ iter 2

**False positives we found and suppressed during testing.** A naive $SI<$FN check produced **157,536
raw "hits"** — almost all benign. We suppressed: null-`$SI` cache files; installer clusters sharing one
$SI; vendor build-before-install gaps (a legitimate Adobe service was *almost* flagged → fixed by
requiring a large backdate **or** a user-writable path); and masquerade noise from `%systemroot%`/bare
command lines (fixed via path canonicalization). Final: **0 false positives.**

**Confirmed vs inferred.** "Confirmed" requires cross-source corroboration (e.g. disk backdating **and**
memory execution); single-source signals are reported as *suspected*, never confirmed. The masquerade is
reported as **disk-resident** precisely because it was **not** seen executing — we don't claim execution.

**Real-case: tool-confirmed vs analyst-inferred (honesty over perfection).**
- *Tool-confirmed (artifact-traceable):* RDP source IP, outbound pivot, USB serials/times, the
  SharePoint→USB download, UserAssist executions, brute-force count — each tied to a logged tool call.
- *Analyst-inferred (NOT claimed as automated findings):* SDelete = anti-forensics *intent*; attribution
  (insider vs external); personal email accounts; and we flag the brute-force burst as likely
  **opportunistic internet noise** (no matching successful logon) rather than over-attributing it.

**Hallucination control.** The agent can only call read-only getters, so every claim must come from a
tool result, and every call is in the audit log. The deterministic engine (not the LLM) is the oracle
for the scored numbers, so accuracy does not depend on model behavior.

Full version: https://github.com/ik-labs/findevil-dfir/blob/main/ACCURACY.md
