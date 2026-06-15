# Agent — autonomous DFIR driver (model-agnostic, Cerebras)

A ReAct-style tool-calling loop that drives the Find Evil! **Custom MCP Server**. The LLM does
orchestration; the forensic logic lives in the read-only MCP tools. Model-agnostic via an
OpenAI-compatible API — here, **Cerebras** (Llama 3.3 70B / Qwen). No Claude/Anthropic dependency.

Rules fit: SANS Find Evil! permits "comparable agentic architectures" and does not mandate a
specific model; our architecture is the listed **Custom MCP Server** approach.

## Why this is safe with a non-Claude / OSS model
The hard reasoning (FP suppression, cross-source corroboration, the self-correction ladder) is
in the deterministic tools/engine, not the model. The agent only decides *which tool to call*
and synthesizes results — and it can ONLY call read-only tools (no shell/write exists), so
evidence integrity is architectural regardless of model. The accuracy numbers and miss→catch
traces come from `engine.py` / `scoring/` (no LLM), so model choice does not affect the claim.

## Run (on the SIFT box)
```bash
export CEREBRAS_API_KEY=sk-...                 # your key
export CEREBRAS_MODEL=gpt-oss-120b             # optional (default; available on Cerebras)
# the MCP server defaults to the injected bodyfile (work/injected/rocba-INJ-01.body),
# so the agent should surface INJ-01 (timestomp) + INJ-02 (masquerade).
python3 agent/agent.py \
  --trace-out ~/cases/rocba/output/traces/agent-run.json
```
Output: the round-by-round tool calls + a FINDINGS report. The full transcript (component #8,
agent execution log) is written to `--trace-out`.

## Env
- `CEREBRAS_API_KEY` (required), `CEREBRAS_MODEL` (default `gpt-oss-120b`),
  `CEREBRAS_BASE_URL` (default `https://api.cerebras.ai/v1`), `FINDEVIL_MCP` (server.py path).

## Verified run (2026-06-12)
`gpt-oss-120b` autonomously called `get_timestomp_candidates → detect_timestomps →
detect_masquerade` and reported BOTH injected contradictions (INJ-01 timestomp, INJ-02
masquerade) with disk+memory provenance. Transcript: `output/traces/agent-run.json`. Free-tier
429s are handled by built-in retry/backoff.

## Wiring check (no key needed)
```bash
python3 agent/_wiring_check.py   # lists the 7 tools, asserts read-only surface
```
