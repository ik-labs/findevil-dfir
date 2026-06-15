# 02 — Baseline Observation (Fill As You Go)

> THE most important early doc. Before building anything, run Protocol SIFT's baseline on
> ROCBA and record *where and how it fails*. These observations (a) become raw material for
> the accuracy report, and (b) tell you which contradiction type to lead with. If the
> baseline already nails something, you pivot away from it.
>
> Rule: write down what you SAW, not what you expected. Surprises are the gold.

## A. Baseline run — straight "find evil"
Run Protocol SIFT's stock agent against ROCBA the way Rob Lee demoed ("find evil").

- Command(s) run:
- Wall-clock time:
- Did it complete / error / stall?
- Output location:

### What it found (verbatim summary)
-

### What it MISSED (cross-check against the FOR500 known findings + your own look)
-

### Where it HALLUCINATED (claims with no artifact backing)
-

### Tool-sequencing observations (did it pick sane tools in a sane order?)
-

## B. Does it cross-reference disk vs memory AT ALL?
This is the crux for our spine. Probe specifically:

- Does the baseline ever load BOTH disk and memory in one investigation? (Y/N)
- Does it ever compare a disk fact against a memory fact? (Y/N)
- If you point it at a disagreement, does it notice? (Y/N)

> If baseline does NOT cross-reference sources → our spine is clearly novel. Good.
> If it does some → note exactly how much, so we differentiate above it.

## C. Self-correction baseline
- Does the stock agent ever re-examine / retry when its output is inconsistent? (Y/N)
- Give a concrete example of a place it *should* have second-guessed and didn't:

## D. The four probe contradictions (manual, before any injection)
For each, manually set up the situation (or find it in ROCBA) and watch the baseline:

| # | Type | Did baseline catch it? | Notes |
|---|------|------------------------|-------|
| 1 | Timestomp ($SI vs $FN / memory) |  |  |
| 2 | Phantom process (mem, no disk file) |  |  |
| 5 | Hash mismatch (masquerade) |  |  |
| 7 | Timeline gap (log wipe vs memory) |  |  |

> Whichever the baseline MOST clearly misses → that's your flagship demo contradiction.
> Hypothesis going in: #1 timestomp (one-shot agents grab $SI and call it benign).

## E. The vacation-window hypothesis (ROCBA-specific)
Fred is provably away 2020-11-10 → 11-13; break-in 2020-11-13. Probe:
- Is there interactive activity on the system during the away window? (Y/N — evidence?)
- Does disk timeline vs memory tell a consistent story about that window? (Y/N)
- Could "activity during provable-absence" be a natural built-in contradiction we exploit?

> CAUTION: this is a hypothesis from the briefing deck, not confirmed from evidence.
> Treat injected contradictions as the reliable floor; vacation-window anomaly = upside.

## F. Decision out of baseline
After A–E, lock these in:
- **Flagship contradiction type for the demo:** ______
- **3 types we'll fully support (depth > breadth):** ______
- **Does the baseline give us a clean "miss" to show miss→catch against?** ______
- **Anything that kills/reshapes the plan?** ______

→ Only after this is filled → proceed to injection (04) and agent build.
