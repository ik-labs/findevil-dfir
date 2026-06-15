# Demo Video Script (≤ 5 min)

**Format the rules require:** a **screencast of live terminal execution with audio narration** —
*not slides, not a marketing video* — showing the agent against **real evidence** with **at least one
self-correction sequence**. Host on **YouTube or Vimeo** (public). Findings must trace to tool executions.

Everything runs from **one script**: `./demo.sh`. You press **Enter** to advance between the four
sections, so you narrate each at your own pace.

## Pre-flight (before you hit record)
- `ssh rocba` → `cd ~/cases/rocba/findevil`
- Make the **terminal font large**; dark theme reads best.
- **Warm the caches** so nothing stalls on camera (run once, discard):
  `curl -s -o /dev/null http://127.0.0.1:8000/api/score` and `…/api/detect` and `…/api/traces`
- **Don't restart the service / reboot** before recording (keeps caches warm).
- Quiet room, decent mic. Target ≈ **4:30**. You may trim the agent's API waits in editing.

## Record
Start recording, then run **one command**:
```bash
./demo.sh
```
Now narrate each section as you press Enter:

### 0:00 – 0:25 — Intro (over the title banner)
> "This is FindEvil, for the SANS Find Evil challenge — the FOR500 Rocba case: a Windows disk image
> and memory capture from a breached host. The problem with agentic DFIR is that 'read-only' is
> usually just a prompt. We made it architectural. Let me show you." *(press Enter)*

### 0:25 – 1:05 — Section 1/4: the read-only guarantee + bypass
*(script runs `agent/_wiring_check.py`)*
> "Here's the agent's entire tool surface — 11 typed, read-only forensic tools. Zero write, shell, or
> delete tools. And watch: when I simulate the agent trying to run a shell, write to the disk image,
> or delete an artifact — every one comes back 'Unknown tool.' It *cannot* modify evidence, because
> the capability doesn't exist. That's a constraint, not a promise." *(press Enter)*

### 1:05 – 2:20 — Section 2/4: self-correction + blind score  ← required sequence
*(script runs `demo_selfcorrection.py`)*
> "Now the self-correction. On a one-shot look, this OneDrive.exe seems like a harmless old file — a
> MISS. But the engine names its own gap: that timestamp comes from a single, forgeable source. So it
> pulls the tamper-resistant $FN time — they disagree by 592 days — then corroborates against memory,
> where the file is actually running. Benign → suspected → confirmed. The same loop catches a
> svchost.exe masquerading outside System32. And it's graded against a key the model never sees:
> zero percent on first impression, 100% after self-correction — zero false positives, zero false
> negatives." *(press Enter)*

### 2:20 – 4:00 — Section 3/4: the autonomous agent on the real case
*(script runs `agent/agent.py` — streams round by round)*
> "Now the autonomous agent — a model-agnostic ReAct loop on an open-source model via Cerebras, no
> Claude dependency. It picks which read-only tool to call; notice the token count logged each round.
> It confirms the two planted contradictions, then reconstructs the *real* intrusion through the same
> read-only surface: remote RDP from 52.249.198.56, a lateral pivot to 172.16.6.18, USB devices, and a
> colleague's SharePoint document pulled down to a USB drive." *(press Enter)*

### 4:00 – 4:25 — Section 4/4: the audit trail
*(script tails `mcp_audit.log`)*
> "Every tool call is logged with a timestamp and the exact artifact it cited — so any finding traces
> straight back to the tool execution that produced it."

### 4:25 – 4:45 — Close
The script prints the dashboard + repo links.
> "There's also a live dashboard that narrates all of this. One honesty note: the planted contradictions
> are blind-scored validation; the real-case kill chain is tool-surfaced, with the interpretive threads
> labeled analyst-corroborated. Code and the live demo are linked below. Thanks for watching."

---

**Checklist:** ✅ live terminal (not slides) · ✅ audio narration · ✅ real evidence · ✅ self-correction
sequence · ✅ findings traceable to tools · ✅ under 5 min · ⬜ upload to YouTube/Vimeo (public) and
paste the link into Devpost.

> Want the individual commands instead of the script? They're in `demo.sh` — run any one by hand.
