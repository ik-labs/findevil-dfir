# Demo Video Script (≤ 5 min)

**Format the rules require:** a **screencast of live terminal execution with audio narration** —
*not slides, not a marketing video* — showing the agent against **real evidence** with **at least one
self-correction sequence**. Host on **YouTube / Vimeo / Youku** (publicly visible). Findings must be
traceable to specific tool executions.

## Before you record
- SSH into the SIFT box and make the **terminal font large**; dark theme reads well on camera.
- `ssh rocba` then `cd ~/cases/rocba/findevil`
- Have the Cerebras key loaded for the agent step: `set -a; . ~/cases/rocba/.cerebras.env; set +a`
- Quiet room / decent mic. Speak the narration; don't read these labels aloud.
- Total target ≈ **4:30**. You can trim dead air during the agent's API waits, but keep it terminal-live.

---

### 0:00 – 0:25 — Context (talk over the terminal)
**Do:** `ls` the repo, show the case is mounted.
> "This is FindEvil, for the SANS Find Evil challenge — the FOR500 Rocba case: a Windows disk image
> and memory capture from a host that was breached. The problem with agentic DFIR is that 'read-only'
> is usually just a prompt. We made it architectural."

### 0:25 – 1:00 — The read-only guarantee
**Do:** `python3 agent/_wiring_check.py`
> "Here's the agent's entire tool surface — 11 typed, read-only forensic tools, and zero write, shell,
> or delete tools. The agent *cannot* modify the evidence, because the capability doesn't exist. This
> is a constraint, not a promise."

### 1:00 – 2:15 — Self-correction + blind-scored accuracy  ← required sequence
**Do:** `python3 demo_selfcorrection.py`
> "Watch the engine self-correct. On a one-shot look, this OneDrive.exe seems like a harmless old file —
> a MISS. But it names its own gap: that creation time comes from a single, forgeable source. So it
> pulls the tamper-resistant $FN timestamp — they disagree by 592 days — then corroborates against
> memory, where the file is actually running. Benign → suspected → **confirmed**. Same loop catches the
> masquerade: a file named svchost.exe living outside System32."
>
> "And it's graded against a ground-truth key the model never sees: zero percent on first impression,
> **100% after self-correction — zero false positives, zero false negatives** across 35 candidates."

### 2:15 – 3:55 — Autonomous agent on the real case
**Do:** `python3 agent/agent.py --trace-out output/traces/agent-run.json`
*(trim the API waits in editing; keep the tool calls visible)*
> "Now the autonomous agent — a model-agnostic ReAct loop on an open-source model via Cerebras, no
> Claude dependency. It decides which read-only tools to call. Notice the per-round timestamps and
> token counts in the log."
>
> "It confirms the two planted contradictions, then reconstructs the **real** intrusion through the
> same read-only surface: remote RDP from 52.249.198.56, a lateral pivot to 172.16.6.18, eight USB
> devices, and a colleague's SharePoint document pulled down to a USB drive. Every line in this report
> traces back to a specific artifact."

### 3:55 – 4:20 — Traceability (audit trail)
**Do:** `tail -n 8 ~/cases/rocba/output/mcp_audit.log`
> "Every tool call is logged with a timestamp and the exact artifact it cited — so any finding traces
> back to the tool execution that produced it."

### 4:20 – 4:40 — (Optional, brief) the dashboard + honest close
**Do:** quick cut to `http://13.235.157.16:8000` (a few seconds only — keep the focus on the terminal).
> "There's also a live dashboard that narrates all of this. One honesty note: the planted contradictions
> are blind-scored validation; the real-case kill chain is tool-surfaced, and the interpretive threads
> are clearly labeled analyst-corroborated. Code and the live demo are linked below. Thanks for watching."

---

## One-line cheat sheet (commands in order)
```bash
ssh rocba
cd ~/cases/rocba/findevil
ls
python3 agent/_wiring_check.py
python3 demo_selfcorrection.py
set -a; . ~/cases/rocba/.cerebras.env; set +a
python3 agent/agent.py --trace-out output/traces/agent-run.json
tail -n 8 ~/cases/rocba/output/mcp_audit.log
```

**Checklist:** ✅ live terminal (not slides) · ✅ audio narration · ✅ real evidence · ✅ ≥1
self-correction sequence · ✅ findings traceable to tools · ✅ under 5 min · ⬜ upload to
YouTube/Vimeo/Youku (public) and paste the link into Devpost.
