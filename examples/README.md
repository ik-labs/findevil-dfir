# Examples

- **`agent-run.sample.json`** — a full agent execution log (submission component #8). A single
  autonomous run of `agent/agent.py` on the ROCBA case: the round-by-round tool-call sequence with
  per-round **timestamps** and **token usage**, each tool result preview, and the final FINDINGS
  report. Every reported finding traces back to the tool call that produced it.

  Regenerate: `python3 agent/agent.py --trace-out output/traces/agent-run.json`
