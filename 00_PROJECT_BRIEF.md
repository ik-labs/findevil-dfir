# 00 — Project Brief (North Star)

> Read this first, every session. If anything below conflicts with something you're about
> to do, stop and re-read. This file is the source of truth for *what we're building and why*.

## The hackathon in one line
SANS **Find Evil!** — make Protocol SIFT a *fully autonomous* incident response agent.
Deadline-driven, $22k prizes. We are optimizing for **podium**, not just shipping.

## What we are building (the thesis)
A **cross-source contradiction detection agent** for DFIR, built as a **Custom MCP Server**
on top of the SIFT Workstation + Protocol SIFT.

Two parts, one system:

- **SPINE (the job + the proof):** Given two evidence sources from the *same* machine
  (disk image + memory capture), the agent cross-references them and flags where they
  **disagree**. Because we *inject known contradictions ourselves*, every test has a
  pre-known right answer. The job and the scoreboard are the same object.

- **ENGINE (the method):** A **self-correction loop** runs *inside* the agent. It attempts,
  checks its own work, logs the gap, adjusts, and re-runs — with a hard `--max-iterations`
  cap so it cannot spiral. The engine is what turns a static "it caught it" into a
  measurable accuracy curve (iter 1 vs final).

C runs inside B. We ship ONE coherent agent and make ONE provable claim.

## Why Custom MCP Server (the architecture decision)
Of the four supported approaches, we chose the Custom MCP Server because:
1. Judges call it "the most sound architecture in the evaluation."
2. It is the ONLY approach that lets us answer the mandatory **evidence-integrity**
   question (submission component #6) with *"architecturally enforced"* instead of
   *"we hoped the prompt held."* The server exposes typed functions like
   `get_amcache()`, `extract_mft_timeline()`, `analyze_prefetch()` — it does **not**
   expose `execute_shell_cmd`, so the agent *physically cannot* run a destructive
   command or write to evidence.
3. It parses raw tool output before returning to the LLM → prevents context-window
   overload on huge text dumps.

Cost: it is the most work. Accepted.

## The one claim we want to be able to make (and prove)
> "We inject N known contradictions across paired disk+memory evidence. The agent catches
> X% on first pass and, through autonomous self-correction, climbs to Y% by iteration K —
> every catch traces to the specific artifact (e.g. `$MFT` offset / `_EPROCESS` struct)
> that produced it, and the MCP server makes evidence modification architecturally
> impossible."

That single claim touches **5 of 6 judging criteria**: IR Accuracy, Breadth/Depth,
Autonomous Execution (tiebreaker), Audit Trail, Constraint Implementation.

## The flagship case: ROCBA
SANS FOR500 "Fred Rocba" case — IP theft via home break-in. Single Windows host,
**disk + memory pair** (the rare thing we need):
- `rocba-cdrive.e01` (22 GB) — disk source
- `Rocba-Memory.zip` (5.3 GB) — memory source
- Background deck already read; Fred is provably **on vacation 2020-11-10 → 11-13**, the
  break-in is 2020-11-13 → there's a built-in "user couldn't have done this" anomaly
  window worth probing.

## The methodology guard (important — these are KNOWN training cases)
ROCBA/VANKO are public SANS training cases; answer keys may exist online and the base
model may have seen walkthroughs. Therefore: an agent "finding the right answer" proves
little. Our **injected contradictions** (novel, planted at byte offsets we document,
absent from any published key) are the unfakeable proof of *genuine reasoning over the
bytes*. State this explicitly in the accuracy report.

## Hard rules (do not violate)
- **Never write to original evidence.** Mount read-only. Work on copies. The MCP server
  must not expose any write/destructive operation over evidence.
- **Every finding must trace to a tool execution.** No finding without a pointer to the
  artifact + offset that produced it.
- **The self-correction loop must have a hard max-iterations cap.** No runaway loops.
- **Honesty over perfection in the accuracy report.** Documented failure modes are signal,
  not weakness.

## Definition of done (MVP that still wins)
A working MCP-server agent that, on ROCBA + injected contradictions:
1. Catches ≥3 contradiction types,
2. Demonstrates ≥1 clean miss→catch self-correction sequence on video,
3. Emits timestamped logs tracing every finding to its artifact,
4. Cannot modify evidence (provable),
5. Ships with the 8 required submission components.

Depth on 3 types beats shallow coverage of 7. Build the vertical slice first.

## The 8 submission components (elimination if any missing)
1. Code repo (GitHub public, MIT/Apache-2.0)
2. Demo video (≤5 min, live terminal + narration, ≥1 self-correction sequence)
3. Architecture diagram (label pattern; distinguish architectural vs prompt guardrails)
4. Written project description (Devpost story format)
5. Dataset documentation (what tested against, source, findings)
6. Accuracy report (FP/FN/hallucinations + evidence-integrity / spoliation section)
7. Try-it-out instructions (reproducible, NOT hosted)
8. Agent execution logs (timestamped, traceable findings)
