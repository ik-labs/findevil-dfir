# FindEvil — the DFIR agent that can't alter evidence

**An autonomous DFIR agent built on a Custom MCP Server that exposes _only_ typed, read-only
forensic tools.** It cross-references what a disk *claims* against what memory *proves* to catch
tampering attackers plant to hide — and it **architecturally cannot modify the evidence**, because
no write/shell/delete tool exists in its surface.

Built for the **SANS "Find Evil!"** challenge on the FOR500 *Fred Rocba / Stark Research Labs* case.

> 🔴 **Live demo:** http://13.235.157.16:8000 — click **RUN INVESTIGATION** (deterministic engine)
> or **🤖 LIVE AI AGENT** (a Cerebras `gpt-oss-120b` model drives the read-only tools in real time).

---

## The wedge: permissions beat prompts

Most "agentic" DFIR setups promise read-only treatment in a *system prompt* while handing the model
a raw shell with write access. That's a request, not a constraint — one bad tool call or prompt
injection from altering evidence.

FindEvil makes integrity a property of the **architecture**: the agent can call typed getters or
nothing. There is no `run_shell`, `write`, or `delete`.

```python
# mcp_server/tools.py — the ONLY callable tools
READ_ONLY_TOOLS = {
  "get_mft_timestamps", "get_timestomp_candidates",
  "get_process_list", "get_process_start", "get_network_connections",
  "detect_timestomps", "detect_masquerade",
  "get_usb_devices", "get_remote_access", "get_web_activity", "get_program_execution",
}   # 11 tools · 0 write/exec — verified by agent/_wiring_check.py
```

## What it does

**1. Catches planted contradictions — and proves it (blind-scored).**
Two adversary-style contradictions are injected at known byte offsets, then detection is scored
against a ground-truth key the model never sees:

| Injection | Type | Signal | Result |
|---|---|---|---|
| `OneDrive.exe` | Timestomp (T1070.006) | `$SI` backdated 591.79d vs `$FN`, contradicted by a live process | ✓ caught @ iter 3 |
| `svchost.exe` | Masquerade (T1036) | system-binary name in a user OneDrive folder, not `System32` | ✓ caught @ iter 2 |

```
catch@iter1 = 0/2 (0%)   →   catch@final = 2/2 (100%)   ·   0 FP · 0 FN · 35 candidates scanned
```

A **self-correction engine** reproduces how a one-shot look misses these and iterates
`benign → suspected → confirmed`.

**2. Reconstructs the real intrusion.**
Through the same read-only surface, the agent surfaces the genuine ROCBA kill chain:
remote **RDP from `52.249.198.56`** → lateral **pivot to `172.16.6.18`** → corporate IP pulled from
SharePoint to **USB (`F:\Files from SRL system`)** → cloud-sync tooling run — plus 8 USB devices and
a 60-hit RDP brute-force burst.

## Architecture

```
 evidence (read-only mount)            deterministic forensic core (the "oracle", no LLM)
 ┌───────────────────────┐            ┌───────────────────────────────────────────────┐
 │ E01 disk  +  RAM image │──extract──▶│ timestomp · spine join (disk⇄memory) ·          │
 │ registry · evtx · Edge │            │ masquerade · self-correction engine · scoring   │
 └───────────────────────┘            └───────────────────────────────────────────────┘
                                                        │ wraps as
                                                        ▼
                                       ┌───────────────────────────────┐    audited,
                                       │  Custom MCP Server (FastMCP)   │    read-only
                                       │  11 typed tools · 0 write/exec │    every call logged
                                       └───────────────────────────────┘
                                                        ▲ tool calls
                                                        │
                            ReAct agent (Cerebras gpt-oss-120b, model-agnostic)
                                                        │
                                       FastAPI + React dashboard (live narration)
```

The hard reasoning lives in the deterministic tools — the model only decides *which* read-only tool
to call. So the system is **model-agnostic** and the accuracy doesn't depend on the LLM.

## Repo layout

| Path | What |
|---|---|
| `extractors/` | timestomp, memory, spine join, masquerade, real-case (USB/RDP/web/exec) |
| `engine/` | self-correction miss→catch engine |
| `mcp_server/` | the Custom MCP Server + the read-only tool surface |
| `agent/` | model-agnostic ReAct agent (Cerebras) + wiring check |
| `scoring/` | key-blind `run_case.py` + the only key-reader `score.py` + `groundtruth.json` |
| `harness/` | inject/verify planted contradictions |
| `webui/` | FastAPI backend + single-file React dashboard |
| `examples/` | sample agent execution log (component #8) — round-by-round, timestamps + token usage |
| `ARCHITECTURE.md` · `ACCURACY.md` | architecture diagram (pattern + guardrails) · accuracy + evidence-integrity report |
| `00`–`05`, `TASKS.md` | working docs / build log (the lab notebook) |

## Quickstart

```bash
# 1) verify the read-only tool surface (no key needed)
python3 agent/_wiring_check.py

# 2) run the autonomous agent (needs structured artifacts on a prepared SIFT box)
export CEREBRAS_API_KEY=...            # your key (OpenAI-compatible Cerebras endpoint)
python3 agent/agent.py --trace-out output/traces/agent-run.json

# 3) the dashboard
cd webui && ./run.sh                    # serves on :8000
```

Evidence prep (SIFT Workstation): `ewfmount` the E01 read-only, TSK `fls` → bodyfile, Volatility 3
(`pslist`/`cmdline`/`netscan`), RegRipper / python-evtx / Edge SQLite → structured JSON the tools read.

## Built with

`python` · `mcp` · `fastmcp` · `cerebras` (`gpt-oss-120b`) · `volatility3` · `sleuthkit` ·
`regripper` · `python-evtx` · `mftecmd` · `ewfmount` · `sift` · `fastapi` · `uvicorn` · `react` ·
`tailwindcss` · `sqlite` · `aws-lightsail` · `systemd`

## Honest scope

The planted contradictions are **validation** (measured against a blind key). The real-case findings
are surfaced by the read-only MCP tools (RDP, USB, web downloads, program execution); the deeper
interpretive threads (SDelete anti-forensics, personal accounts, who/why) are **analyst-corroborated**
and labeled as such in the UI. The SANS FOR500 evidence and course material are not redistributed here.

## License

[MIT](LICENSE)
