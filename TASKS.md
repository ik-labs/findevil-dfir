# TASKS — Find Evil! Build Tracker

> Phased checklist for the whole build. Work top to bottom; don't skip phase gates.
> Mark `[x]` when done, add a date. The `★` items are the load-bearing ones — if a `★`
> fails, stop and resolve before moving on. Keep this in `~/cases/rocba/docs/` next to the
> other docs and update it as you go (it's also raw material for the Devpost write-up).

Legend:  `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked · `★` critical gate

---

## STATUS @ 2026-06-12  (deadline Jun 15, 11:45pm EDT)
**Build essentially complete.** 2 contradiction types (timestomp #1, masquerade #5) work end to
end: inject → detect via typed read-only MCP tools → cross-source corroborate → self-correct
miss→catch → score vs a key the model never sees. 30 tests green. Accuracy: **iter-1 0% → final
100%, 0 FP / 0 FN** across 35 candidates.

| Phase | State |
|------|-------|
| 0 Planning | ✅ DONE |
| 1 Environment bring-up | ✅ DONE (caveat: box Claude Code not yet auth'd → blocks Phase 2 only) |
| 2 Baseline observation | ⬜ PENDING — optional (recon done); note: live agent now runs on Cerebras, not Claude |
| — Autonomous agent | ✅ DONE — agent/agent.py (gpt-oss-120b via Cerebras) drives the MCP server, catches both injections live |
| 3 Plant + verify | ✅ DONE (INJ-01) |
| 4 MCP server | ✅ DONE (7 read-only tools, audit log, no-write proof) |
| 5 Spine (cross-source) | ✅ DONE |
| 6 Engine (self-correction) | ✅ DONE |
| 7 Scoring harness | ✅ DONE |
| 8 Validation breadth | 🟡 PARTIAL — #5 masquerade added; real-findings + memory types are stretch |
| 9 Submission package | ⬜ PENDING — the main remaining work (8 components; #8 logs done) |

**Critical path to a valid submission = Phase 9** (mostly assembly from existing artifacts +
demo video + repo push/license). Phase 2 and the rest of Phase 8 are optional/stretch.

---

## PHASE 0 — Planning  (DONE)
- [x] Pick flagship case → ROCBA (disk + memory pair)
- [x] Pick architecture → Custom MCP Server
- [x] Pick thesis → cross-source contradiction detection (spine) + self-correction loop (engine)
- [x] Generate doc set 00–05 + README
- [x] Build this task tracker

---

## PHASE 1 — Environment bring-up  (DONE 2026-06-12)  (ref: 01_ENVIRONMENT_SETUP.md)
**Goal: empty box → SIFT + Protocol SIFT running, evidence in place.**
**Status: COMPLETE** — env ready; only baseline-agent-auth pending (see gate note below).

### Provision
- [x] Spin up Lightsail: Ubuntu 22.04.5 LTS, 16GB RAM / 4 vCPU / 320GB SSD (2026-06-12)
- [x] ★ Confirm SSH into the box from Mac (2026-06-12) — used pem-key SSH alias `rocba`
      (static IP 13.235.157.16), NOT Twingate. Key `~/.ssh/rocba.pem`.
- [x] ★ Confirm Claude Code on Mac can run commands on the box (2026-06-12) — drive via `ssh rocba`
- [x] `apt update && upgrade`; install curl/wget/unzip/git/build-essential/python3-pip/jq (2026-06-12)
- [x] Confirm resources: 4 vCPU / 15 GiB / 309 GB free (2026-06-12)

### Install SIFT (via cast — sift-cli is deprecated)
- [x] Verify exact `cast` install command (2026-06-12) — cast v1.0.19 .deb from ekristen/cast
- [x] Install `cast`; run `sudo cast install --mode=server teamdfir/sift-saltstack` (2026-06-12)
      → 724/724 salt states OK
- [x] ★ Sanity-check tools present: Volatility 3 (`vol`), Sleuth Kit (fls/mmls/mactime/istat),
      plaso (log2timeline.py/psort.py), ewfmount, 7z (2026-06-12)
- [x] Record exact commands that worked in 05_BUILD_LOG.md (2026-06-12)

### Install Protocol SIFT (the baseline we improve)
- [x] Run `curl -fsSL .../teamdfir/protocol-sift/main/install.sh | bash` (2026-06-12)
- [x] Document what the script installs + WHERE its agent loop / prompts / tool wrappers live
      (2026-06-12) — it's a Claude Code CONFIG in `~/.claude/`: global CLAUDE.md (agent loop),
      settings.json (guardrails), 5 skills (tool wrappers). See 05 build log "thesis-critical".
- [~] ★ Confirm the stock Protocol SIFT agent runs at all — BLOCKED: Claude Code 2.1.175 installed
      on box but NOT yet authenticated. Need `ssh -t rocba 'cd ~/cases/rocba && claude'` + login.

### Get ROCBA evidence (order: memory first, then disk)
- [x] `mkdir -p ~/cases/rocba/{evidence,work,output,docs}` (2026-06-12)
- [x] Download `Rocba-Memory.zip` (5.68GB); note format (2026-06-12) — NESTED: zip → Rocba-Memory.7z
      → `Rocba-Memory.raw` (18GB raw dump). Downloaded direct-to-box from Egnyte (no auth needed).
- [x] Download `rocba-cdrive.e01` (23.6GB) (2026-06-12) — single NTFS volume, no MBR/GPT
- [x] ★ Set `evidence/` read-only (`chmod -R a-w`) (2026-06-12)
- [x] ★ Mount disk image READ-ONLY (2026-06-12) — ewfmount→ewf1 (offset 0, single NTFS vol);
      ntfs-3g needed dm-linear zero-pad fix (recipe in 05). Write attempt → "Read-only file system".
- [x] ★ Point Volatility at memory image (2026-06-12) — `vol -f Rocba-Memory.raw windows.info` OK:
      Win10 build 19041 x64, 4 CPUs, capture 2020-11-16 02:32:38 UTC.

**PHASE 1 GATE:** all `★` checked → environment ready. **DONE 2026-06-12**, with one caveat:
baseline-agent-runs (★) is pending Claude Code auth on the box — does not block Phase 3
(plant+verify, which uses TSK directly), but must be resolved before Phase 2 baseline runs.

---

## PHASE 2 — Baseline observation  (ref: 02_BASELINE_OBSERVATION.md)
**Goal: watch Protocol SIFT FAIL on ROCBA; pick the flagship contradiction.**

- [ ] Run stock "find evil" on ROCBA; record time, completion, output
- [ ] Record what it FOUND / MISSED / HALLUCINATED
- [ ] ★ Determine: does baseline cross-reference disk vs memory at all? (decides our novelty)
- [ ] Determine: does baseline ever self-correct? Find a spot it should have and didn't
- [ ] Run the 4 probe contradictions (#1/#2/#5/#7); fill the catch/miss table
- [ ] Probe the vacation-window hypothesis (activity during Fred's provable absence?)
- [ ] ★ LOCK decisions: flagship contradiction type, the 3 types to fully support,
      confirm there's a clean "miss" to demo miss→catch against
- [ ] Log surprises in 05_BUILD_LOG.md

**PHASE 2 GATE:** flagship contradiction chosen + baseline failure confirmed. If baseline
already nails everything, reshape the plan here (not later).

---

## PHASE 3 — Plant + verify (vertical-slice de-risk)  (DONE 2026-06-12)  (ref: 04)
**Goal: prove plant-and-detect works on ONE contradiction, from Linux, no Windows.**
**Status: COMPLETE — INJ-01 planted, verified, and caught end-to-end (confirmed_timestomp).**

- [x] ★ Working copy in `work/injected/` (2026-06-12) — extracted $MFT (icat ewf1 0, 469MB),
      not an 87GB image copy; original evidence untouched
- [x] Locate target MFT record + record `$SI`/`$FN` (2026-06-12) — OneDrive.exe, entry 104046,
      chosen because it has a LIVE process in real memory (genuine corroboration)
- [x] ★ Inject timestomp: backdate `$SI` only, leave `$FN` (2026-06-12) — harness/inject_timestomp.py;
      $SI 2020-10-27→2019-03-15, $FN intact, byte 106543184
- [x] ★ VERIFY: re-parse → `$SI` backdated, `$FN` real (2026-06-12) — independent re-parse confirmed
- [x] Fill the GROUND-TRUTH KEY for INJ-01 (2026-06-12) — scoring/groundtruth.json + table in 04
- [x] Confirm anti-leakage (2026-06-12) — key in scoring/, NOT in agent working dir/context
- [x] BONUS: full spine on injected-disk + REAL memory → `confirmed_timestomp`, both provenances,
      0 false confirmations. extractors/ pipeline + 10 regression tests green.

**PHASE 3 GATE:** ✅ planted `$SI`≠`$FN` read back AND caught by the spine → approach de-risked.

---

## PHASE 4 — MCP server (the architectural guardrail)  (DONE 2026-06-12)  (ref: 05 Appendix A)
**Goal: typed, read-only functions the agent calls instead of raw shell.**
**Status: COMPLETE — mcp_server/ (FastMCP, stdio), verified over the MCP protocol.**

- [x] Scaffold the MCP server; language/runtime = Python + FastMCP (extractors are Python) (2026-06-12)
- [x] ★ Expose ONLY typed read-only funcs; NO execute_shell_cmd, NO write ops (2026-06-12) —
      test_no_write_or_exec_capability proves the registered set == read-only registry
- [x] Disk funcs: get_mft_timestamps(path)->{SI,FN}, get_timestomp_candidates() (2026-06-12)
- [x] Memory funcs: get_process_list(), get_process_start(pid) (2026-06-12)
- [x] get_network_connections() (2026-06-12). [get_file_hash/autorun/eventlog: deferred to breadth]
- [x] Each func parses raw tool output → structured result (2026-06-12)
- [x] ★ Each func emits an audit line: ts + tool + args + artifact ref → output/mcp_audit.log (2026-06-12)
- [x] ★ Prove evidence unmodifiable: server has no write/exec tool (registry assertion) (2026-06-12)
- [x] BONUS: detect_timestomps (cross-source spine) exposed as a tool; full MCP client round-trip
      catches INJ-01 with both provenances. findevil/.mcp.json registration written. 18 tests green.

**PHASE 4 GATE:** ✅ agent can ONLY get typed facts; every call logged & traceable; no write path exists.

---

## PHASE 5 — Spine (cross-source comparison)  (DONE 2026-06-12)
**Goal: normalize disk+memory facts → flag contradictions, traced to artifacts.**
**Status: COMPLETE — extractors/spine.py + timestomp.py + memory.py + masquerade.py.**

- [x] Implement the normalization schema (2026-06-12) — memory.normalize_path() reduces
      disk + memory paths to one comparable tail; findings carry source/value/provenance
- [x] Implement consistency rules (2026-06-12) — $SI≪$FN backdating + memory-execution
      corroboration (timestomp); system-binary name vs canonical path (masquerade)
- [x] ★ End-to-end on INJ-01: reads $SI+$FN+memory → flags the timestomp (2026-06-12) —
      confirmed_timestomp, matched live pid 9648
- [x] Every flag carries provenance (2026-06-12) — $MFT entry + _EPROCESS PID on every finding
- [x] Extend to the other supported types (2026-06-12) — #5 masquerade added (full slice)

**PHASE 5 GATE:** ✅ catches the flagship (and a 2nd) contradiction with a traceable finding.

---

## PHASE 6 — Engine (self-correction loop)  (DONE 2026-06-12)
**Goal: miss→catch by iterating, with a hard cap.**  **Status: COMPLETE — engine/engine.py.**

- [x] Implement attempt → self-check → log gap → adjust → re-run loop (2026-06-12)
- [x] ★ Hard `--max-iterations` cap — no runaway; cap-hit = honest miss (2026-06-12)
- [x] Terminate on resolved/confirmed OR cap-hit ("unresolved — needs human") (2026-06-12)
- [x] ★ Preserve FULL timestamped iteration traces → output/traces/INJ-01.trace.json (2026-06-12)
- [x] ★ Clean miss→catch on INJ-01: benign → suspected_timestomp → confirmed_timestomp,
      caught at iter 3 (2026-06-12). 4 engine tests (14 total) green.

**PHASE 6 GATE:** ✅ measurable climb — iter-1 catch-rate 0% (miss) → iter-3 100% (catch) on INJ-01.

---

## PHASE 7 — Scoring harness (verifiable, not blind)  (DONE 2026-06-12)
**Goal: turn runs into numbers, separate from the agent.**  **Status: COMPLETE.**

- [x] ★ Separate harness vs the key, agent never sees key (2026-06-12) — run_case.py (key-blind)
      + score.py (the only key reader); enforced by SEPARATION
- [x] Compute per-type: catch iter-1 vs final, FP, FN (2026-06-12)
- [x] Fill the accuracy matrix in 03_CONTRADICTION_TAXONOMY.md (2026-06-12) — row 1 timestomp
- [x] Run across injected contradictions → catch-rate curve (2026-06-12) — INJ-01:
      iter1 0% → final 100%, FN=0, FP=0 across 34 candidates. 4 scoring tests (22 total) green.

**PHASE 7 GATE:** ✅ headline claim with real numbers: 0% one-shot → 100% via self-correction, 0 FP/FN.

---

## PHASE 8 — Validation breadth  (IN PROGRESS 2026-06-12)
**Goal: guard against overfitting to your own injections.**

- [x] Add a 2nd contradiction type: #5 masquerade (T1036) — full slice inject→detect→engine→MCP→score
      (2026-06-12). Matrix now 2 rows; both show iter1 0% → final 100%, 0 FP/FN. 34 tests green.
- [x] FP-control validated on REAL ROCBA: masquerade detector → 0 hits on stock evidence (no
      false alarms); timestomp → 0 false confirmations across 34 candidates (2026-06-12).
- [ ] Run agent against ROCBA's REAL findings (not just injected) → does it hold up?
- [ ] (Stretch) Probe memory-dependent types (#2/#3/#4) if real memory supports them
- [ ] (Stretch) Sanity-run on a second case (VANKO) for breadth

---

## PHASE 9 — Submission package (8 components — miss one = elimination)
**Goal: assemble all required deliverables. Reproducible, not hosted.**

- [ ] #1 Code repo: GitHub public + MIT/Apache-2.0 license (visible in About) + README setup
- [ ] #2 Demo video ≤5min: live terminal + narration + ≥1 self-correction sequence
- [ ] #3 Architecture diagram: label pattern; distinguish architectural vs prompt guardrails
- [ ] #4 Project description: Devpost story (what/how/challenges/learned/next) from 05 log
- [ ] #5 Dataset docs: ROCBA source + injected ground-truth key + what was found
- [ ] #6 Accuracy report: FP/FN/hallucinations + evidence-integrity (read-only/MCP) + spoliation test
- [ ] #7 Try-it-out: step-by-step to run locally on SIFT (reproducible) + dependencies in README
- [ ] #8 Execution logs: timestamped, every finding traceable to its tool execution
- [ ] ★ Final check: all 8 present, repo public, license detectable, video public on YouTube

**PHASE 9 GATE:** submit before deadline (Jun 15, 11:45pm EDT). All 8 in.

---

## RISK / WATCH LIST (revisit each session)  — reviewed 2026-06-12
- [x] Disk headroom — 68G used / 243G free (22%). Dodged e01→raw balloon: inject edits the
      extracted $MFT (469MB), not an 87GB raw; ewfmount is a sparse FUSE view. OK.
- [x] RAM / OOM — 14Gi available, nothing heavy running. OK.
- [!] Lightsail STOP between sessions — instance currently RUNNING. ACTION: stop it when paused
      (static IP + evidence persist). Only the user can do this.
- [x] Known-case credibility — accuracy claim leads with INJECTED INJ-01/02 (novel byte offsets). OK.
- [x] Anti-leakage holding — run_case.py is key-blind; only score.py reads groundtruth.json. OK.
- [x] Evidence pristine — evidence/ read-only (dr-xr-xr-x / -r--r--r--), sizes + embedded MD5/SHA1
      intact; all injection on the extracted-MFT copy. (Formal proof: `ewfverify` ~10min.) OK.

## OPEN QUESTIONS — RESOLVED (answers logged in 05)
- [x] Exact `cast` install + sig-validation — cast v1.0.19 .deb (ekristen/cast); cosign-verified
      by cast itself; `sudo cast install --mode=server teamdfir/sift-saltstack` (724/724 states)
- [x] What Protocol SIFT installs / where its loop lives — it's a Claude Code CONFIG in ~/.claude/
      (global CLAUDE.md = loop, settings.json = guardrails, 5 skills = tool wrappers)
- [x] ROCBA memory format → Volatility invocation — Rocba-Memory.raw (18GB), Win10 19041 x64;
      `vol -f <raw> windows.info` (run with `2>/dev/null`; vol = /usr/local/bin/vol = Vol3)
- [x] `.e01` editing / mount — single NTFS volume (no MBR/GPT), offset 0; mount needs dm-linear
      zero-pad fix (recipe in 05). For injection we edit the EXTRACTED $MFT (no full-image copy).
- [~] Does real memory exhibit #2/#3/#4 — not yet probed for phantom/ghost/deleted; masquerade
      scan of real memory = 0 (none in stock). Stretch (Phase 8).
