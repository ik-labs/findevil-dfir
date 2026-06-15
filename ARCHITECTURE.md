# Architecture

**Architectural pattern: `Custom MCP Server`.** (Of the four options — Direct Agent Extension,
**Custom MCP Server**, Multi-Agent Framework, Alternative Agentic IDE — this is a Custom MCP Server:
forensic capability is exposed to a model-agnostic agent purely as typed MCP tools.)

Components: **evidence sources → SIFT extraction → deterministic forensic core → Custom MCP Server
(read-only) → autonomous agent → output pipeline.** The hard logic lives in the deterministic core
and is exposed only through typed, read-only MCP tools (0 write/exec) — so the agent (any model) can
investigate but **cannot modify evidence**.

### Guardrails: architectural, not prompt-based

| Guardrail type | Typical approach | This project |
|---|---|---|
| **Prompt-based** (what we avoid) | "Please treat evidence as read-only" in a system prompt, while a shell/write tool still exists | ❌ not relied on |
| **Architectural** (what we use) | The capability to modify simply **does not exist** in the tool surface | ✅ 0 write/exec tools; bypass attempts return *"Unknown tool"* (see `agent/_wiring_check.py`) |

In the diagram below, the **Custom MCP Server** node is the single chokepoint: the agent can reach
evidence *only* through its 11 read-only tools. The dashed boundary is enforced by **absence of
capability**, not by instructions to the model.

```mermaid
flowchart LR
  subgraph EV["Evidence — read-only mount"]
    E01["Disk image (E01)"]
    MEM["Memory capture"]
    REG["Registry hives<br/>SYSTEM / NTUSER"]
    EVT["Event logs<br/>Security / TerminalServices"]
    WEBH["Edge history (SQLite)"]
  end

  subgraph PREP["SIFT extraction (read-only)"]
    TSK["Sleuth Kit fls<br/>→ $MFT bodyfile"]
    VOL["Volatility 3<br/>pslist / cmdline / netscan"]
    RR["RegRipper"]
    EVTX["python-evtx"]
    SJSON[("Structured JSON<br/>artifacts")]
  end

  subgraph CORE["Deterministic forensic core — no LLM"]
    EXT["Extractors<br/>timestomp · spine join · masquerade<br/>usb · rdp · web · execution"]
    ENG["Self-correction engine<br/>miss → catch"]
    SCO["Scoring<br/>key-blind run + blind key"]
  end

  subgraph MCPS["Custom MCP Server — FastMCP, stdio"]
    TOOLS["11 typed READ-ONLY tools<br/>0 write / exec"]
    AUD[("Audit log")]
  end

  AGENT["Autonomous agent<br/>ReAct loop · Cerebras gpt-oss-120b<br/>(also Claude Code / Protocol SIFT compatible)"]

  subgraph OUT["Output pipeline"]
    REP["FINDINGS report<br/>structured narrative"]
    TRACE[("Execution log + traces<br/>timestamps · token usage")]
    UI["FastAPI + React<br/>live dashboard"]
  end

  E01 --> TSK
  MEM --> VOL
  REG --> RR
  EVT --> EVTX
  WEBH --> SJSON
  TSK --> SJSON
  VOL --> SJSON
  RR --> SJSON
  EVTX --> SJSON

  SJSON --> EXT
  EXT --> ENG
  EXT --> SCO
  ENG --> SCO

  EXT --> TOOLS
  ENG --> TOOLS
  SCO --> TOOLS
  TOOLS --> AUD

  AGENT <==>|read-only tool calls| TOOLS
  TOOLS --> REP
  AGENT --> REP
  AUD --> TRACE
  REP --> UI
  TRACE --> UI
  SCO --> UI
```

**How to export as an image for Devpost:** paste this block at <https://mermaid.live>, then
*Actions → Export PNG* (or SVG). GitHub also renders it inline on this page.
