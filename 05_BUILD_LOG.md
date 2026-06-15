# 05 — Build Log (Append-Only Lab Notebook)

> Dated entries: what you did, what broke, what you learned. Append only — never delete.
> This is where the Devpost "Challenges / What you learned" sections get written from, in
> real time, instead of reconstructed from memory at the end. Be specific about surprises.

## Format
```
### YYYY-MM-DD — <short title>
- DID:
- BROKE:
- LEARNED:
- NEXT:
```

---

### 2026-06-__ — Day 0: planning locked
- DID: Chose flagship case (ROCBA, disk+memory pair). Chose architecture (Custom MCP Server).
  Chose thesis (cross-source contradiction detection = spine; self-correction loop = engine).
  Generated doc set 00–05.
- LEARNED: ROCBA/VANKO are known SANS FOR500 cases → injected contradictions are essential
  for credible accuracy claims, not optional.
- NEXT: Provision Lightsail (Ubuntu 22.04, 16GB/4vCPU/100GB+), bring up SIFT via cast,
  install Protocol SIFT, download memory zip then disk e01.

### 2026-06-12 — Phase 1: environment bring-up on Lightsail
- DID: Provisioned Lightsail Ubuntu 22.04.5 (4 vCPU / 15 GiB / 309 GB), static IP
  13.235.157.16, SSH alias `rocba` (key ~/.ssh/rocba.pem). Installed base tools + `cast`
  v1.0.19 (.deb from ekristen/cast), then `cast install --mode=server teamdfir/sift-saltstack`
  → 724/724 salt states OK. Downloaded both ROCBA files direct-to-box from the Egnyte
  share (no auth needed on the /dd/ entryId links): Rocba-Memory.zip (5.68 GB),
  rocba-cdrive.e01 (23.6 GB). Locked evidence/ read-only. Installed Protocol SIFT.
- BROKE/SURPRISES:
  - Memory evidence is a NESTED archive: Rocba-Memory.zip → Rocba-Memory/Rocba-Memory.7z
    → Rocba-Memory.raw (~16 GB raw dump). Needs 7z (present via SIFT). Extracted into
    work/memory/extracted/ (evidence stays pristine).
  - cast/SIFT put Volatility 3 at `/usr/local/bin/vol`. But the baseline Protocol SIFT
    CLAUDE.md insists Vol3 = `python3 /opt/volatility3-2.20.0/vol.py` and says
    `/usr/local/bin/vol.py` is Vol2. RECONCILE the real Vol3 path before memory analysis.
- LEARNED (thesis-critical — baseline recon):
  Protocol SIFT is NOT a bespoke agent — it is a Claude Code CONFIG for DFIR. Installer drops
  into ~/.claude/: global CLAUDE.md (the "agent loop"/system prompt), settings.json +
  settings.local.json (the guardrails), and 5 skills (memory-analysis, plaso-timeline,
  sleuthkit, windows-artifacts, yara-hunting = markdown "tool wrappers" that tell Claude how
  to run vol/fls/log2timeline/yara), plus generate_pdf_report.py + a case template.
  THE WEDGE: its evidence-integrity is a PROMPT-vs-PERMISSION CONTRADICTION. CLAUDE.md says
  "Strict read-only, never modify evidence," but settings.json allows `Bash(*)` with
  defaultMode=acceptEdits and explicitly allows `Bash(mount *)`, `losetup`, redirection. The
  deny-list only blocks dd/rm -rf/wget/curl/ssh/WebFetch. So NOTHING architecturally prevents
  a write to evidence — only the model obeying the prompt = literally "we hoped the prompt
  held." This is exactly the gap our Custom MCP Server closes (component #6): expose ONLY
  typed read-only funcs, no Bash → evidence modification is impossible by construction.
  (Also note: baseline is air-gapped — curl/wget/ssh/WebFetch denied → can't look up answers.
  And it has a Stop hook appending ./analysis/forensic_audit.log.)
- RESOLVED (Phase 1 complete):
  - Vol3 path = `/usr/local/bin/vol` (Volatility 3 Framework 2.28.0). There is NO vol.py;
    the baseline CLAUDE.md's "/opt/volatility3-2.20.0/vol.py" / "vol.py is Vol2" note is stale.
  - Memory: Rocba-Memory.raw = 18 GB raw dump. `vol -f Rocba-Memory.raw windows.info` OK →
    Windows 10 build 19041 x64, 4 CPUs, SystemTime 2020-11-16 02:32:38 UTC (capture is 3 days
    AFTER the 11-13 break-in; vacation window 11-10→11-13 precedes it). Symbols auto-fetched
    (box has internet for analysis; agent stays air-gapped per baseline deny-list).
    NOTE: vol writes Progress to STDERR with \r — always run `vol ... 2>/dev/null` when capturing.
  - Disk: the e01 is a SINGLE NTFS VOLUME image (no MBR/GPT) — `mmls` fails, `fsstat ewf1` works
    at offset 0. Vol name "Windows", Win10 (Program Files, Users, Windows.old, Windows10Upgrade).
  - MOUNT GOTCHA (non-obvious, reusable): ntfs-3g failed "Failed to read last sector" — the
    NTFS boot sector declares the volume ~6 sectors larger than the raw ewf1 (truncated image),
    and there is no ntfs3 kernel module on the AWS kernel (6.8.0-aws). FIX (fully read-only):
      LOOP=$(sudo losetup --read-only --find --show work/ewf/ewf1)
      SZ=$(sudo blockdev --getsz $LOOP)
      printf "0 %s linear %s 0\n%s 64 zero\n" $SZ $LOOP $SZ | sudo dmsetup create rocba_ntfs
      sudo mount -o ro,show_sys_files,streams_interface=windows /dev/mapper/rocba_ntfs work/mnt
    dm-linear pads 64 zero sectors so the last-sector read succeeds; every layer is read-only
    (evidence file ro → ewfmount ro → loop ro → dm ro → mount ro). Write attempt to mnt →
    "Read-only file system". For forensic parsing we mostly use TSK directly on ewf1 anyway.
  - NOTE for analysis: hiberfil.sys + pagefile.sys present on disk; Windows.old present
    (possible artifact-rich area).
- NEXT: Phase 2 baseline observation — run stock Protocol SIFT (cd into a case dir, `claude`)
  on ROCBA, watch it fail / not cross-reference disk vs memory; confirm a clean miss to demo
  miss→catch against. (Claude Code on box will need auth first.) Then Phase 3 plant+verify on
  the timestomp vertical slice.

### 2026-06-12 — Context-size measurement + the false-positive finding (decides model question)
- DID: Measured the real token footprint of forensic context on ROCBA to decide Claude-Code
  vs local-OSS-LLM. Generated structured artifacts in output/structured/ and measured
  (~tokens = bytes*2/7 ≈ bytes/3.5):
  | Artifact                                   | rows      | ~tokens     |
  |--------------------------------------------|-----------|-------------|
  | DISK timeline RAW (fls -r -m, all files)   | 1,117,303 | 72,000,000  |
  | DISK filtered to exec+dll                  | 104,396   | 6,648,000   |
  | DISK created in absence window (11-09..17) | 214,529   | 15,886,000  |
  | Naive $SI<$FN "timestomp" detector         | 157,535   | 6,549,000   |
  | MEM pslist verbose vol JSON                | 2,189     | 208,993     |
  | MEM pslist compact TSV                     | 2,189     | 29,825      |
  | NET netscan trimmed TSV                    | 430       | 6,820       |
  | Properly discriminated anomalies (target)  | ~tens     | hundreds–low-k |
- BROKE/SURPRISES:
  - pslist returns 2,186 UNIQUE PIDs (not a parse artifact) — abnormally high for one
    workstation; pslist is walking terminated _EPROCESS still resident. Worth investigating
    (long uptime vs. something spawning many procs). Conservative worst-case for sizing.
  - THE FALSE-POSITIVE FINDING (now a centerpiece of the accuracy report): the naive
    "$SI creation < $FN creation = timestomp" rule yields 157,535 hits — and nearly all are
    SI=1970-01-01 (epoch 0) APPLICATION CACHE files (Firefox cache2, Slack/Teams/Edge/Chrome
    Code Cache, Office TapCache, Service Worker). These are benign: apps wrote a null $SI
    crtime. ZERO are real timestomps (and there's no injected one in the stock image yet).
    => naive cross-referencing drowns in false positives; disciplined, memory-corroborated
    detection (the spine) is what works. This IS the evidence that the project's thesis matters.
  - Bodyfile pairing gotcha: $SI and $FN lines share the base MFT entry but differ in the
    attribute suffix of TSK's inode field (e.g. 376952-128-4 for $DATA vs 376952-48-2 for
    $FILE_NAME). Must key on the substring before the first "-" to pair them. fls -r -m DOES
    emit $FN times (lines tagged " ($FILE_NAME)") — so the bodyfile already carries SI+FN.
- LEARNED (the model decision, settled empirically):
  1. Context size is NEVER the Claude blocker — a well-discriminated finding set is KBs;
     Claude's 200k window is 10–100x headroom. Token cost is a non-issue with pre-parsing +
     bounded runs (+ subscription auth = $0 marginal).
  2. The hard part is MODEL-AGNOSTIC: you cannot feed 72M tokens (or the 157k-FP pile) to
     ANY LLM (Claude or OSS). Both need the server to discriminate BEFORE the LLM sees data.
     That extraction/discrimination layer is the actual engineering — build it first; it
     doesn't commit us to a model.
  3. Where the LLM choice matters is JUDGMENT not volume: separating 1 real timestomp from
     157,535 cache-file FPs is subtle reasoning — exactly where Opus/Sonnet >> a CPU-bound
     7B OSS model on this no-GPU box. So once context is small, Claude is MORE justified.
  => DECISION: stay on Claude Code; build the structured-extraction/discrimination layer now.
- NEXT: build get_timestomp_candidates() as the first real extractor (MCP tool core) — refined
  to exclude null-SI (epoch-0) + cache/noise dirs, prioritise executables, classify confidence.
  Then memory-corroborate (cross-ref FN-recent creation vs process start) = the spine.

### 2026-06-12 — First extractor: get_timestomp_candidates() (the spine's disk half)
- DID: Built `extractors/timestomp.py` — the first real extraction/discrimination function
  (core of the future MCP tool). Parses a TSK bodyfile (`sudo fls -r -m C: ewf1`), pairs
  $SI vs $FN crtime per MFT entry, flags backdated $SI (timestomp signature T1070.006),
  and classifies confidence with FP-suppression learned from the 157k-FP finding:
  drop null-$SI (epoch0 cache), exclude shared-$SI installer clusters (≥8 files same second,
  e.g. the 2002-02-01 Office/VSTO media date), require user-writable location for HIGH.
  Emits compact JSON + provenance ($MFT entry ref) for the audit trail. CLI + module API.
- RESULT on real ROCBA bodyfile (455,359 paired MFT entries, 157,536 naive mismatches):
    high=2  medium=31  low=790  installer=23,581  noise=133,102  null_si=30
  i.e. 157,536 → 2 HIGH, and the 2 are BENIGN vendor bundles (Adobe setup.exe, a Grammarly
  DLL — vendor build-date < install-date). Correct: there is NO injected timestomp in the
  stock image yet, so HIGH≈0 is the right answer. Validated it FIRES on a true positive via
  a synthetic backdated Temp/evil.exe (→ high, 681d, full provenance). 5 regression tests
  (extractors/tests/test_timestomp.py) lock in fire-on-TP + suppress-the-3-FP-classes. All pass.
- LEARNED: disk-side detection alone gets to 2 residual FPs but CANNOT fully separate vendor
  backdating from malicious timestomping — because the discriminator is execution: a real
  timestomp's backdated file actually RUNS (process start ≈ recent $FN), a bundled DLL does
  not. This is concrete proof the cross-source spine (memory corroboration) is necessary, not
  decorative. Code lives in the repo at extractors/ (this dir becomes the GitHub submission).
- NEXT: memory half — get_process_start(pid)/get_process_list() from Volatility, then the
  spine join: for each HIGH timestomp candidate, check if a live process runs from that path
  with start≈$FN (confirm) vs no execution (downgrade to benign vendor artifact). Then Phase 3:
  inject a real timestomp on a working copy and watch the full pipeline catch it.

### 2026-06-12 — Memory extractor + the spine join (cross-source timestomp pipeline)
- DID: Built the memory half and the cross-source join — the SPINE is now end-to-end.
  - extractors/memory.py: get_process_list()/get_process_start() over Volatility 3
    (windows.pslist for pid/ppid/name/start/exit + windows.cmdline for the launch PATH;
    pslist alone only gives the basename which is too weak to join on). normalize_path()
    reduces 'C:\\...', '\\Device\\HarddiskVolumeN\\...', 'C:/...' to one comparable tail.
    On ROCBA: 197 processes resolved a launch path (incl. tools/mrc.exe = the RAM capturer).
  - extractors/spine.py: corroborate() joins each disk timestomp candidate to memory by
    normalized path (basename fallback) and compares process start vs $SI/$FN. Verdicts:
    confirmed_timestomp | running_vendor_pattern | running_ambiguous | basename_match_only
    | no_execution. Every finding carries BOTH provenances ($MFT entry + _EPROCESS PID).
  - 10 regression tests across timestomp + spine (extractors/tests/), all green.
- BROKE/SURPRISES (important, goes in the accuracy report):
  - First spine run "confirmed" Adobe armsvc.exe — a FALSE POSITIVE. It's the legit Acrobat
    Update Service: $SI=2020-09-06 (build), $FN=2020-10-27 (install), auto-starts as a service
    (so it's running). LESSON: memory-execution corroboration is NECESSARY BUT NOT SUFFICIENT —
    tons of legit vendor software has build-date($SI) < install-date($FN) AND runs (Adobe, Zoom,
    Grammarly all showed the same pattern). A 50d gap in Program Files is not an attack.
  - FIX: "confirmed" now also requires the backdating be implausible for a vendor build/install
    gap — a large backdate (>=365d) OR a user-writable (payload-drop) location. Adobe armsvc
    correctly downgrades to running_vendor_pattern. The fully robust discriminator is
    Authenticode code-signing (a future extractor) — noted in the verdict reasoning.
- RESULT on stock ROCBA (33 medium+high disk candidates, 197 procs): 0 confirmed_timestomp,
  1 running_vendor_pattern (Adobe), 32 no_execution. ZERO false confirmations — the correct
  baseline, because there is NO injected timestomp in the stock image yet. Synthetic injected
  timestomp (user-writable Temp/evil.exe, running) -> confirmed_timestomp (test-locked).
- LEARNED: this is the credibility argument in miniature — on a real known case with no planted
  evil, the pipeline raises 0 false alarms; it only "confirms" when disk backdating + live
  execution + implausible-for-vendor all line up. That's why INJECTED ground truth (Phase 3) is
  how we MEASURE catch-rate, and why honest FP reporting (the Adobe story) belongs in the report.
- NEXT: Phase 3 — inject a real timestomp on a WORKING COPY of the disk (backdate $SI of a
  binary that corresponds to a process already resident in the real memory, so memory genuinely
  corroborates), run the full spine, confirm catch + write the ground-truth key. Stretch: an
  Authenticode-signature extractor to clear the vendor-pattern bucket outright.

### 2026-06-12 — Phase 3 DONE: timestomp plant → detect → corroborate (vertical slice de-risked)
- DID: Planted and caught the first injected contradiction (INJ-01), full pipeline.
  - Efficient injection (no 87GB copy): extracted the real $MFT (`sudo icat ewf1 0` → 469MB,
    479,488 entries) into work/injected/Rocba-INJ-01.mft. In an extracted $MFT, record N is
    always at byte N*1024 — no data-run math.
  - harness/inject_timestomp.py: parses the NTFS MFT record, backdates ONLY the
    $STANDARD_INFORMATION creation FILETIME, leaves $FILE_NAME untouched. Target = OneDrive.exe
    (entry 104046) because it has a LIVE process in the real memory (so corroboration is genuine,
    not faked) and sits in a user-writable AppData path.
  - INJECTED: $SI 2020-10-27T02:56:48Z → 2019-03-15T08:00:00Z (backdate 591.79d). $FN unchanged
    at 2020-10-27. Byte offset 106543184 in the extracted MFT. Verified by independent re-parse.
  - MFTECmd regenerated the bodyfile from the injected $MFT — and it uses the SAME TSK
    "($FILE_NAME)"-tagged format, so extractors/timestomp.py + spine.py consumed it unchanged.
  - RAN extractors/spine.py on injected-disk bodyfile + REAL memory:
    => confirmed_timestomp for entry 104046: matched live pid 9648 (OneDrive.exe) start
       2020-11-11T08:14, "607d after forged $SI but ~15d from true $FN", provenance on BOTH
       legs ($MFT entry 104046 + _EPROCESS PID 9648). 0 false confirmations on the same run.
- GROUND TRUTH: scoring/groundtruth.json (machine oracle) + the filled table in 04. ANTI-LEAKAGE
  enforced: scoring/ and docs/ are NOT inside the agent's working dir/context; scoring is a
  separate post-run step.
- LEARNED: the extracted-$MFT + MFTECmd path is the reusable injection rig — fast, byte-authentic,
  reproducible, and it sidesteps multi-GB image copies AND read-only-mount fragility entirely.
  The plant→detect→corroborate loop is now proven; everything downstream (engine, scoring,
  breadth) builds on a working slice.
- NEXT: Phase 4/5 packaging — wrap timestomp.py/memory.py/spine.py as the Custom MCP Server
  (typed read-only tools: get_timestomp_candidates / get_process_list / detect_timestomps), then
  Phase 6 engine (miss→catch self-correction: iter1 reads only $SI → benign; iterN reads $FN +
  memory → catch) and Phase 7 scoring harness vs scoring/groundtruth.json.

### 2026-06-12 — Phase 6 DONE: the self-correction ENGINE (miss -> catch, hard cap, traces)
- DID: Built engine/engine.py — the self-correction loop. attempt -> self-check -> log gap ->
  adjust (pull one more evidence source) -> re-run, with a hard --max-iterations cap and a full
  timestamped trace (component #8). Evidence ladder for timestomp: (1) $SI alone, (2) +$FN,
  (3) +memory execution. Self-checks encode methodology ($SI alone is forgeable; disk backdating
  is stronger if execution corroborates).
- RESULT on INJ-01 (entry 104046):
    ACCURACY CURVE: benign -> suspected_timestomp -> confirmed_timestomp   (caught at iter 3)
  iter1 reads only $SI (2019-03-15) -> "aged file, benign" = the one-shot MISS; self-check flags
  single-source reasoning -> iter2 pulls $FN (mismatch, ~592d) -> suspected; iter3 corroborates
  with live pid 9648 -> confirmed, both provenances. Trace saved output/traces/INJ-01.trace.json.
- GUARDRAILS validated + test-locked (4 engine tests, 14 total green):
  * HARD CAP: --max-iterations 1 -> "unresolved (benign) — needs human", terminated=max_iterations.
    The engine does NOT guess past the cap (the honest miss = quantifies one-shot failure).
  * NO FALSE CATCH: original un-injected entry ($SI==$FN) -> benign -> benign, resolved at iter2.
  * DISK-ONLY: backdated file with no live process -> stops at no_execution, not confirmed.
- LEARNED: this is the measurable accuracy claim in one object — iter-1 catch-rate 0% (miss) ->
  iter-3 100% (catch) for INJ-01, with the climb driven by the engine recognising its own gaps.
  The same trace is the demo climax AND component #8. The "needs human" cap behaviour is the
  honesty guarantee judges look for (no runaway, no hallucinated certainty).
- NEXT: Phase 4 — wrap extractors as the Custom MCP Server (typed read-only tools); Phase 7 —
  scoring harness vs scoring/groundtruth.json (agent never sees the key); then breadth
  (#5 hash-mismatch / #7 timeline-gap) and the submission package.

### 2026-06-12 — Phase 4 DONE: the Custom MCP Server (the architectural guardrail)
- DID: Built the Custom MCP Server (Python, FastMCP, stdio) — the submission centerpiece.
  - mcp_server/tools.py: typed read-only functions wrapping the validated extractors, each
    returning STRUCTURED data (no raw-dump context overload) and writing an AUDIT line
    (ts + tool + args + artifact refs) per call.
  - mcp_server/server.py: registers exactly 6 tools — get_mft_timestamps, get_timestomp_candidates,
    get_process_list, get_process_start, get_network_connections, detect_timestomps. NO
    run_shell/exec/write/delete tool exists. Evidence-integrity is ARCHITECTURAL (component #6).
  - findevil/.mcp.json: Claude Code registration.
- VERIFIED:
  * MCP protocol round-trip (initialize -> list_tools -> call_tool) via a real stdio client:
    lists the 6 tools; detect_timestomps -> confirmed_timestomp on INJ-01 (OneDrive.exe) with
    both provenances ($MFT entry 104046 + _EPROCESS PID 9648). This is exactly what the agent does.
  * Audit log output/mcp_audit.log accumulates one JSON line per call (timestamp + artifacts).
  * 4 server tests incl. test_no_write_or_exec_capability: the registered tool set == the
    read-only registry, names are all get_/detect_, and no shell/exec/write entry point exists.
    (mcp SDK installed via pip; FastMCP.)
- LEARNED: separating tools.py (plain audited functions) from server.py (thin FastMCP shell)
  made the whole surface unit-testable without an MCP client, and the no-write proof becomes a
  simple registry assertion — the cleanest way to evidence "architecturally enforced" for judges.
- NEXT: Phase 7 scoring harness (grade agent/spine output vs scoring/groundtruth.json, agent never
  sees the key) -> the accuracy matrix; then breadth (#5 hash-masquerade / #7 timeline-gap) and the
  8-component submission package (repo/README, demo video, arch diagram, accuracy report, write-up).

### 2026-06-12 — Phase 7 DONE: scoring harness (the accuracy numbers)
- DID: Built the two-part scoring flow with anti-leakage by SEPARATION:
  * scoring/run_case.py — runs detection + engine over all candidates, records per-iteration
    verdicts + final verdict. NEVER reads the key (the system being graded can't see answers).
  * scoring/score.py — the separate grader; reads run output + scoring/groundtruth.json, computes
    TP/FN/FP and catch@iter1 vs catch@final. Only this component touches the key.
  * 4 scoring tests (22 total green).
- RESULT (INJ-01): injections=1, catch@iter1=0 (0%), catch@final=1 (100%), FN=0, FP=0.
  INJ-01 timestomp = TP, caught@iter 3. The 0 FP is across all 34 investigated candidates
  (Adobe/Grammarly/Zoom vendor build<install files correctly stay non-confirmed) — precision holds
  case-wide, not just on the target. Filled the accuracy matrix row in 03.
- LEARNED: this is the whole claim made measurable and reproducible — "0% one-shot → 100% via
  self-correction, 0 FP/FN" — and the run/score split is the concrete artifact proving the model
  never saw the answer key. Outputs: output/run-INJ-01.json, output/accuracy-INJ-01.json.
- NEXT: breadth — add a 2nd contradiction type (#5 hash-masquerade or #7 timeline-gap) to widen the
  matrix from 1 row to 2-3; then the 8-component submission package (repo README + license, demo
  video of the miss->catch, architecture diagram, accuracy report from this matrix, write-up).

### 2026-06-12 — Breadth: contradiction type #5 masquerade (T1036) — 2nd type, end to end
- DID: Added the masquerade type across the whole stack (detector → injector → engine → MCP →
  scoring), mirroring the timestomp slice.
  - extractors/masquerade.py: flags system-binary names (svchost/lsass/...) outside their
    canonical System32/SysWOW64 path. scan_memory (process name vs path) + scan_disk (MFT name
    vs path, filtered: excludes WinSxS/servicing/Windows.old/prefetch + requires user-writable).
    Cross-ref: disk masquerade that is also running -> confirmed_masquerade.
  - harness/inject_masquerade.py: in-place $FN rename in the $MFT (new name <= old, no resize).
    INJ-02: entry 104210 OneDriveStandaloneUpdater.exe -> svchost.exe (both 8.3 + long names),
    in C:/Users/fredr/AppData/Local/Microsoft/OneDrive/. MFTECmd regenerated the bodyfile.
  - engine.investigate_masquerade: miss->catch ladder — iter1 TRUSTS the name ("svchost.exe =
    system process, benign"), iter2 checks the PATH vs canonical -> masquerade. (The taxonomy's
    exact "name-based matching trusts the filename" blind spot.)
  - MCP: detect_masquerade exposed as a 7th typed read-only tool.
- BROKE/FIXED: first masquerade run on real ROCBA gave 6 FPs — native processes whose cmdline
  path is "%systemroot%\\system32\\..." (not canonicalized) or a bare basename (no dir). Fixed
  normalize_path to canonicalize %systemroot%/%windir%/\SystemRoot\ -> /windows, and skip
  hits with no directory info. Real ROCBA -> 0 masquerade FPs (correct, none planted in stock).
- RESULT (both types scored vs key): 2 injections, catch@iter1 0% -> catch@final 100%, FN=0,
  FP=0 across 35 candidates. INJ-01 timestomp TP @iter3; INJ-02 masquerade TP @iter2.
  12 new tests (masquerade detector 5, engine masquerade 3, + integration); 34 tests total green.
- LEARNED: the architecture generalised cleanly — a 2nd contradiction type slotted into the same
  inject->detect->engine->MCP->score pipeline with a per-type evidence ladder, and the FP-control
  discipline (canonicalization, exclusion dirs, user-writable gating) carried over. Two rows in the
  accuracy matrix now, both showing the self-correction climb. Depth-first paid off.
- NEXT: the 8-component submission package — repo README + license, demo video (miss->catch on
  both types), architecture diagram, accuracy report (from the 2-row matrix), Devpost write-up,
  try-it-out, execution logs (output/traces + mcp_audit.log).

### 2026-06-12 — Autonomous agent on Cerebras (model-agnostic) — live, catches both injections
- DID: Built agent/agent.py — a ReAct tool-calling loop that drives our Custom MCP Server with a
  non-Claude model via Cerebras (OpenAI-compatible). Rules-checked first: SANS Find Evil! permits
  "comparable agentic architectures", names Custom MCP Server as a supported approach, and does
  NOT mandate a model ("if another agentic framework can do the job, we won't disqualify it").
- VERIFIED LIVE (model gpt-oss-120b): the agent autonomously called get_timestomp_candidates ->
  detect_timestomps -> detect_masquerade and produced a FINDINGS report catching BOTH injected
  contradictions — INJ-01 timestomp (OneDrive.exe, $SI backdated 592d, corroborated by live pid
  9648) and INJ-02 masquerade (svchost.exe in OneDrive AppData) — each with disk+memory provenance
  (MFT entry + _EPROCESS PID) and "never trust a single source" reasoning. 4 rounds, 3 tool calls.
  Full transcript -> output/traces/agent-run.json (submission component #8).
- BROKE/FIXED: (1) cmdline default model "llama-3.3-70b" 404 — this account exposes gpt-oss-120b
  + zai-glm-4.7; set gpt-oss-120b as default. (2) Cerebras free tier returns 429 queue_exceeded
  under load — added retry/backoff (8 tries, exp). Auth worked first try (csk- key in .cerebras.env,
  chmod 600, outside the repo).
- LEARNED: the architecture's payoff lands — because all the hard forensic logic is in the typed
  read-only MCP tools, a NON-Claude OSS model orchestrates it correctly with no quality loss, and
  it physically cannot touch evidence (only read-only tools are reachable). The accuracy numbers
  still come from the deterministic engine/scorer; the agent is the autonomous-execution layer.
  This satisfies the hackathon's Autonomous Execution criterion without any Anthropic dependency.
- NOTE: the Cerebras key was pasted in the chat session — rotate it post-hackathon.
- NEXT: Phase 9 packaging — repo README + license + push, accuracy report (from the 2-row matrix),
  architecture diagram (MCP guardrail + agent + engine + scorer), demo video (agent live run +
  engine miss->catch), dataset docs, try-it-out.

<!-- append new entries above this line as you go -->

---

# Appendix A — MCP Server architecture spec (the thing we're building)

> Reference for Claude Code while implementing. Keep aligned with 00_PROJECT_BRIEF.md.

## Component shape
```
  evidence (read-only)
   ├── disk: rocba-cdrive.e01  ── ewfmount/ro-mount ─┐
   └── memory: <mem image>     ── Volatility ────────┤
                                                      ▼
                          ┌──────────────────────────────────────┐
                          │  Custom MCP Server (the guardrail)     │
                          │  Exposes ONLY typed, read-only funcs:  │
                          │   get_mft_timestamps(path) -> {SI,FN}   │
                          │   extract_mft_timeline()                │
                          │   get_process_list()  (from memory)     │
                          │   get_process_start(pid)                │
                          │   get_network_connections()             │
                          │   get_file_hash(path)                   │
                          │   get_autorun_keys()                    │
                          │   get_eventlog_window(t1,t2)            │
                          │  NO execute_shell_cmd. NO write ops.    │
                          │  Parses raw tool output -> structured.  │
                          └──────────────────┬───────────────────┘
                                             ▼  (typed facts only)
                          ┌──────────────────────────────────────┐
                          │  Agent (Claude Code) — SPINE+ENGINE    │
                          │  SPINE: normalize facts -> compare      │
                          │         disk vs memory -> flag conflicts│
                          │  ENGINE: attempt -> self-check ->        │
                          │          log gap -> adjust -> re-run     │
                          │          (hard --max-iterations cap)     │
                          └──────────────────┬───────────────────┘
                                             ▼
                       timestamped logs  +  flagged findings (each traced to artifact)
                                             ▼
                          ┌──────────────────────────────────────┐
                          │  Scoring harness (SEPARATE)            │
                          │  compares findings vs ground-truth key │
                          │  -> catch-rate per iteration, FP/FN    │
                          └──────────────────────────────────────┘
```

## Why this satisfies the judging criteria
- **Constraint Implementation:** guardrail is ARCHITECTURAL — server exposes no destructive/
  write ops, so evidence modification is physically impossible (not a prompt request).
  This is the direct answer to component #6's evidence-integrity question.
- **Audit Trail:** every typed function call is logged with timestamp + the artifact
  (offset/MFT entry/_EPROCESS) it touched → any finding traces back to a tool execution.
- **Autonomous Execution (tiebreaker):** the engine loop reasons, fails, self-corrects.
- **IR Accuracy:** scored against the injected ground-truth key + ROCBA known findings.
- **Breadth/Depth:** depth across the contradiction types we fully support.

## Normalization schema (the technical heart of the spine)
Reduce BOTH disk facts and memory facts to one comparable shape:
```json
{ "artifact": "evil.exe",
  "source": "disk" | "memory",
  "event": "created" | "process_start" | "connection" | "deleted" | ...,
  "value": "<timestamp | ip | hash | path>",
  "provenance": { "tool": "istat", "ref": "MFT#12345 $SI offset 0x..." } }
```
A contradiction = two facts about the same `artifact` whose `value`s are inconsistent under
a rule (e.g. created-time >> process-start-time). `provenance` is what makes it traceable.

## Self-correction loop contract
- MUST have `--max-iterations` (hard cap). No runaway.
- Each iteration: produce findings → run consistency checks → if a check fails, log the gap
  to a progress file → adjust approach (e.g. "I read $SI; now read $FN") → re-run.
- Terminate on: contradiction resolved/confirmed, OR max-iterations hit (then flag
  "unresolved — needs human" rather than guessing).
- Preserve FULL iteration traces (that's submission component #8 AND the demo's climax).

## Anti-leakage (repeat — it matters)
The agent and MCP server must NOT have access to the ground-truth key (04). Scoring is a
separate post-run step. Leaking answers to the model invalidates every accuracy number.
