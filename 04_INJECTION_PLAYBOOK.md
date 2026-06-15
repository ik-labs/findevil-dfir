# 04 — Injection Playbook (Plant + Verify from Linux)

> How to plant contradictions into evidence WITHOUT a Windows machine, and — just as
> important — how to VERIFY the plant (confirm SIFT reads back your edit). The plant-and-
> verify loop must work on ONE contradiction (#1 timestomp) before you build the agent
> around it. That's the load-bearing experiment.
>
> Golden rule: NEVER edit the original evidence. Always work on a COPY. The originals in
> `evidence/` stay pristine and read-only. Injected copies live in `work/injected/`.

## 0. Working copy discipline
```bash
mkdir -p ~/cases/rocba/work/injected
# Make a working COPY of the disk image (or a smaller extracted slice if size is a problem)
cp ~/cases/rocba/evidence/rocba-cdrive.e01 ~/cases/rocba/work/injected/rocba-INJ-01.e01
# Originals stay read-only (set in 01). Document every injection in the ground-truth key below.
```
> Note: .e01 is a forensic container with internal hashing. Editing inside it may require
> converting to raw first, editing, then (optionally) re-imaging. Decide per-tool whether you
> operate on a raw export or a re-wrapped image. Record what you actually did.

## 1. Flagship: inject a TIMESTOMP (#1) — the vertical-slice experiment

### What changes, conceptually
NTFS stores timestamps in TWO attributes per file:
- `$STANDARD_INFORMATION` ($SI) — the timestamps Explorer/most tools show; what attackers
  forge with timestomping.
- `$FILE_NAME` ($FN) — often retains the TRUE creation time; harder to forge, updated by
  the OS on MFT operations.
Timestomp = backdate `$SI` while `$FN` (and the live memory process start) still tell truth.

### Plant it (from Linux)
Candidate tooling (verify availability/behavior on the box — these change):
- The Sleuth Kit (`istat`, `fls`, `icat`) to LOCATE the target file's MFT record and read
  its current `$SI`/`$FN` timestamps and byte offsets.
- `analyzeMFT` / `MFTECmd` (if present) to parse `$MFT` and confirm record structure.
- A Python NTFS lib (e.g. `libfsntfs`/`pytsk3`) or a small hex-edit script to overwrite the
  `$SI` creation timestamp bytes at the known offset on the RAW image copy.

Procedure:
1. Pick a target binary you "drop" (or an existing file to backdate).
2. `istat` it → record MFT entry number + current `$SI` and `$FN` timestamps + byte offsets.
3. Overwrite ONLY the `$SI` creation timestamp on the raw copy (leave `$FN` intact).
4. Record old→new values in the ground-truth key (below).

### VERIFY the plant (critical — proves plant-and-detect works)
```bash
# Re-parse the injected copy and confirm:
#  - $SI now shows the BACKDATED time
#  - $FN still shows the REAL (recent) time
istat <injected-image-or-mount> <mft-entry>     # compare $SI vs $FN
```
If `$SI` != `$FN` in the way you planted → SIFT reads your edit → the contradiction is real
and detectable. THIS is the moment the whole approach is de-risked. Log it in 05.

## 2. Hash mismatch (#5) — disk-side, from Linux
- Place a non-system binary named `svchost.exe` (or similar) in a non-standard path on the
  mounted copy; record its real hash.
- Ground truth: legit System32 hash vs your planted hash + the wrong path.
- Verify: `fls`/`icat` to extract, `sha256sum` to confirm mismatch; confirm path via MFT.

## 3. Timeline gap (#7) — disk-side, from Linux
- Identify the Windows event log (`.evtx`) on the mounted copy; remove/blank a window of
  records (offline edit on the raw copy), record the exact [t1]→[t2] gap.
- Ground truth: the window you wiped + the activity that should appear there.
- Verify: parse the `.evtx` and confirm the gap; confirm memory (or another disk artifact)
  still shows activity in that window.

## 4. Registry persistence (#6) — disk-side, from Linux
- Mount the copy; edit a registry hive offline (e.g. `python-registry`/`reglookup` to read,
  a hive editor to write) to add an autorun key pointing to path A while the "running"
  artifact is at path B.
- Ground truth: key → path A, actual → path B.
- Verify: re-read the hive, confirm the key; confirm the path-B artifact exists.

## 5. Memory-dependent types (#2 phantom, #3 ghost conn, #4 deleted-resident)
Forging memory convincingly is hard. Options, in order of preference:
1. Find these already present in ROCBA's real memory capture (best — real evidence).
2. Source from a public memory sample known to exhibit them.
3. Defer (they're stretch; the 4 disk-anchored types above are enough for a strong submission).
Do NOT fake memory crudely — a SANS judge will spot an implausible memory image instantly.

---

## GROUND-TRUTH KEY (the answer sheet — keep this rigorous)
> One row per injected contradiction. This file IS your accuracy oracle. Keep it OUT of
> anything the agent can read during a run (no leaking the answers to the model).

> AUTHORITATIVE machine-readable oracle: `scoring/groundtruth.json` (kept OUT of agent runs).
> Table below mirrors it for humans.

| inj-id | type | image | target (file/key/log) | what was planted | old value | new value | byte offset / MFT entry | expected agent conclusion |
|--------|------|-------|------------------------|------------------|-----------|-----------|--------------------------|----------------------------|
| INJ-01 | timestomp (T1070.006) | Rocba-INJ-01.mft | C:/Users/fredr/AppData/Local/Microsoft/OneDrive/OneDrive.exe | backdated `$SI` creation; `$FN` left intact | `$SI`=2020-10-27T02:56:48Z | `$SI`=2019-03-15T08:00:00Z | MFT entry **104046**, byte **106543184** (rec 104046×1024 + `$SI` content 80) | Timestomp: `$SI` backdated ~592d vs `$FN`; live OneDrive.exe process start (~2020-11-11) corroborates true-recent creation → `confirmed_timestomp`, HIGH |
| INJ-02 | masquerade (T1036) | Rocba-INJ-01.mft | C:/Users/fredr/AppData/Local/Microsoft/OneDrive/svchost.exe | renamed `$FN` (both 8.3 + long) to a system-binary name | name=`OneDriveStandaloneUpdater.exe` | name=`svchost.exe` | MFT entry **104210** (`$FN` name bytes) | Masquerade: `svchost.exe` in a user OneDrive dir, not System32/SysWOW64 → `masquerade` by name+location; not running → disk-resident |

**Plant-and-verify RESULT (2026-06-12):** Injected via `harness/inject_timestomp.py` (real byte
edit of the extracted `$MFT`). Verified `$SI`=2019-03-15, `$FN`=2020-10-27 intact. MFTECmd
regenerated the bodyfile; `extractors/spine.py` on injected-disk + REAL memory returned exactly
`confirmed_timestomp` for entry 104046 (pid 9648, both provenances), with 0 false confirmations.
The vertical slice (plant → detect → cross-source corroborate → traceable finding) is DE-RISKED.

## Anti-leakage rule
The agent must NEVER have access to this ground-truth key during analysis. Scoring is done
by a SEPARATE harness that compares agent output against this key after the run. Otherwise
your accuracy numbers are meaningless (and a judge will call it out).
