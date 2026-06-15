#!/usr/bin/env bash
# FindEvil — one-shot demo for the screencast.
# Run on the SIFT box:   cd ~/cases/rocba/findevil && ./demo.sh
# Press Enter to advance between sections (so you can narrate each one).

cd "$(dirname "$0")" || exit 1
TRACE="$HOME/cases/rocba/output/traces/agent-run.json"
AUDIT="$HOME/cases/rocba/output/mcp_audit.log"

# load the Cerebras key for the live-agent section (kept outside the repo)
[ -f "$HOME/cases/rocba/.cerebras.env" ] && { set -a; . "$HOME/cases/rocba/.cerebras.env"; set +a; }

c() { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }
pause() { echo; c "96;1" "▶ press Enter for — $1"; read -r _; echo; }

clear
c "96;1" "══════════════════════════════════════════════════════════════════"
c "96;1" "  FIND EVIL — read-only MCP DFIR agent   ·   SANS FOR500 ROCBA case"
c "90"   "  cross-references disk vs memory · cannot modify evidence by design"
c "96;1" "══════════════════════════════════════════════════════════════════"

pause "1/4 · the read-only guarantee + a live bypass attempt"
c "90" "# The agent's ENTIRE tool surface — and what happens if it tries to write/delete:"
python3 agent/_wiring_check.py 2>/dev/null

pause "2/4 · self-correction (miss → catch) + blind-scored accuracy"
c "90" "# The engine starts naive, names its own gap, and corrects across sources — no LLM:"
python3 demo_selfcorrection.py 2>/dev/null

pause "3/4 · autonomous agent (live · Cerebras gpt-oss-120b) on the real case"
c "90" "# Model-agnostic ReAct loop. It decides which read-only tool to call; tokens logged per round:"
python3 agent/agent.py --trace-out "$TRACE" 2>/dev/null

pause "4/4 · the audit trail — every finding traces to a tool call"
c "90" "# Each tool call logged with a timestamp and the artifact it cited:"
tail -n 10 "$AUDIT"

echo
c "92;1" "✅ demo complete"
c "96"   "   live dashboard: http://13.235.157.16:8000"
c "96"   "   code:           https://github.com/ik-labs/findevil-dfir"
