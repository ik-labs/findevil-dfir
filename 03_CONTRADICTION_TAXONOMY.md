# 03 — Contradiction Taxonomy (Harness Design)

> The seven forensically-meaningful disk-vs-memory disagreements. Each is a "lie" you can
> plant (or find) and a correct agent must catch. This is BOTH the harness design and the
> backbone of the accuracy report. Build order is ranked at the bottom.
>
> Caveat: "disk says X, memory says Y" is grounded in real DFIR tradecraft, but validate
> each is cleanly plantable + detectable with the actual SIFT toolset on the box. Some are
> trivial; one or two are harder than they look on paper.

---

## 1. Timestomp  (MITRE T1070.006)  — FLAGSHIP
- **Lie:** Disk `$MFT` `$SI` timestamp says the file is old; the `$FN` timestamp and the
  in-memory process start time say it's new.
- **Why it matters:** Most common anti-forensic technique — backdate malware to blend with
  system files and evade timeline analysis.
- **Plant:** Drop a binary, backdate its `$SI` creation time, launch it (resident in RAM).
  (Injectable from Linux via `$MFT` byte edit — see 04.)
- **Correct conclusion:** "Visible creation time forged; true creation (`$FN` + memory
  process start) is recent. High-confidence timestomp."
- **Why it catches one-shot agents out:** they grab the obvious `$SI` field, call it benign,
  move on. Cleanest miss→catch for the demo.

## 2. Phantom process (memory-only execution)  (T1055 / T1055.012)
- **Lie:** A process runs in memory with no corresponding executable on disk.
- **Why it matters:** Fileless malware / process hollowing — signature of sophisticated
  actors avoiding disk.
- **Plant:** Run a memory-only payload, or inject into a legit process.
- **Correct conclusion:** "Running process has no backing file on disk. Fileless execution
  or hollowing — high priority."
- **Hard because:** agent must notice an ABSENCE (memory fact with no disk counterpart),
  harder than noticing a presence. Needs real memory evidence — harder to forge.

## 3. Ghost network connection
- **Lie:** Memory shows an active/recent connection to an external IP; disk-side logs
  (firewall, Sysmon, browser history) have no record.
- **Why it matters:** C2 beaconing that evaded logging, or log tampering. RAM is harder to
  fake than a log is to delete.
- **Plant:** Establish a connection, ensure the log entry is absent/deleted.
- **Correct conclusion:** "Memory shows connection to [IP] with no log entry. Possible C2
  with log evasion."
- **Needs real memory evidence.**

## 4. Deleted-on-disk, resident-in-memory
- **Lie:** A file is deleted on disk (marked free / carved deleted) but its contents — or
  the process that used it — are still live in memory.
- **Why it matters:** Attackers delete tools after use; memory retains what disk discarded.
- **Plant:** Run a tool, delete from disk, capture memory while remnants persist.
- **Correct conclusion:** "File deleted from disk but recoverable from memory. Recovered
  artifact: [hash]. Cleanup attempt."
- **Needs real memory evidence.**

## 5. Hash mismatch (impersonation/masquerade)  (T1036)
- **Lie:** A file named like a legit system binary (e.g. `svchost.exe`) has a hash that
  doesn't match known-good; memory shows it loaded from a non-standard path.
- **Why it matters:** Malware posing as trusted system processes.
- **Plant:** Place a renamed/modified binary masquerading as a system file; run from the
  wrong directory. (Disk-side injectable from Linux.)
- **Correct conclusion:** "`svchost.exe` running from `C:\Users\...` (legit:
  `C:\Windows\System32`), hash mismatch. Masquerading — high confidence."
- **Catches out:** name-based matching trusts the filename. Needs name+path+hash correlation.

## 6. Registry persistence vs. active process  (T1547)
- **Lie:** An autorun key on disk points to a persistence binary, but the named binary isn't
  where the key says — yet something matching it runs in memory from elsewhere.
- **Why it matters:** Persistence is how attackers survive reboots; discrepancies reveal
  active tampering.
- **Plant:** Create an autorun key; have the actual payload run from a different location.
  (Registry hive editable offline from Linux.)
- **Correct conclusion:** "Autorun key references [path A]; matching process runs from
  [path B]. Persistence present and active."
- **Hard because:** 3-way chain (registry → disk file → memory process), easy to do
  incompletely.

## 7. Timeline gap (anti-forensic log wipe)  (T1070)
- **Lie:** Disk event log has a blank window (no events), but memory artifacts (recently-run
  programs, in-memory prefetch, command history) show activity DURING that window.
- **Why it matters:** Indicator removal — attackers clear logs to hide dwell time. The gap
  itself is evidence; memory proves it's artificial.
- **Plant:** Do activity, clear the event log for that window, capture memory retaining proof.
  (Log entries deletable offline from Linux.)
- **Correct conclusion:** "Event log gap [t1]→[t2], but memory shows execution during that
  window. Consistent with log clearing."
- **Catches out:** absence-of-logs reads as "nothing happened." Agent must treat a GAP as
  suspicious and corroborate against memory.

---

## Accuracy-report matrix (this table ~= your accuracy report)
| # | Type | MITRE | Source of truth | Catch iter 1? | Catch final? |
|---|------|-------|-----------------|:---:|:---:|
| 1 | Timestomp | T1070.006 | `$FN` + memory | ✗ (0/1) | ✓ (1/1) |
| 2 | Phantom process | T1055 | memory absence on disk |  |  |
| 3 | Ghost connection | — | memory vs logs |  |  |
| 4 | Deleted-resident | — | memory recovery |  |  |
| 5 | Hash mismatch / masquerade | T1036 | name + path | ✗ (0/1) | ✓ (1/1) |
| 6 | Registry persistence | T1547 | 3-way chain |  |  |
| 7 | Timeline gap | T1070 | gap vs memory |  |  |

Goal shape: many dashes in "iter 1", checkmarks in "final" = the self-correction story,
quantified per technique.

**Scored result (INJ-01 + INJ-02, 2026-06-12)** — produced by `scoring/run_case.py` (key-blind)
graded by `scoring/score.py` vs `scoring/groundtruth.json`:
- **2 injected contradictions, iteration-1 catch rate 0% → final catch rate 100%, 0 FN, 0 FP**
  across **35 investigated candidates**.
- INJ-01 timestomp: one-shot reads `$SI` alone → "benign"; engine reaches `confirmed_timestomp`
  at iter 3 via `$FN` + memory corroboration.
- INJ-02 masquerade: one-shot trusts the name `svchost.exe` → "benign"; engine reaches
  `masquerade` at iter 2 by correlating the name against its canonical System32 path.
- Vendor build<install files (Adobe/Grammarly/Zoom) correctly NOT confirmed — the FP suppression.
- Reproduce: `python3 scoring/run_case.py <injected.body> <structured_dir> --out run.json`
  then `python3 scoring/score.py run.json`.

## Build order (don't build all 7 at once)
1. **#1 Timestomp** — easiest to plant from Linux, clearest miss→catch. Get the ENTIRE
   pipeline working end-to-end on this one (extract → normalize → compare → self-correct →
   score). This is your vertical slice.
2. **#5, #7, #6** — all disk/registry/log-side, injectable from Linux without a Windows box.
   These give you 4 solid disk-anchored contradictions even if memory-side ones prove hard.
3. **#2, #4, #3** — memory-dependent; tackle only if real memory evidence supports them or
   you can source them. Stretch.

If only 3 work well → still a complete, provable, podium-capable submission.
Depth on a few beats shallow coverage of many (judging criteria reward this explicitly).
